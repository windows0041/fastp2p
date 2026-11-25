#include "service_unit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One rendering buffer per kind. A unit is a few hundred bytes, so a fixed
 * buffer keeps this translation unit free of allocation policy and of the
 * snprintf(NULL, 0, ...) idiom that MSVC does not implement. */
#define UNIT_SPACE 4096

int fp_service_kind(const char *name) {
    if (!name || !*name)
        return FP_SERVICE_NONE;
    if (!strcmp(name, "systemd"))
        return FP_SERVICE_SYSTEMD;
    if (!strcmp(name, "procd"))
        return FP_SERVICE_PROCD;
    if (!strcmp(name, "openrc"))
        return FP_SERVICE_OPENRC;
    if (!strcmp(name, "launchd"))
        return FP_SERVICE_LAUNCHD;
    return FP_SERVICE_NONE;
}

const char *fp_service_name(int kind) {
    switch (kind) {
    case FP_SERVICE_SYSTEMD: return "systemd";
    case FP_SERVICE_PROCD: return "procd";
    case FP_SERVICE_OPENRC: return "openrc";
    case FP_SERVICE_LAUNCHD: return "launchd";
    default: return "none";
    }
}

const char *fp_service_unit_path(int kind) {
    switch (kind) {
    case FP_SERVICE_SYSTEMD: return "/etc/systemd/system/fastp2p-client.service";
    case FP_SERVICE_PROCD:
    case FP_SERVICE_OPENRC: return "/etc/init.d/fastp2p";
    case FP_SERVICE_LAUNCHD: return "/Library/LaunchDaemons/top.fastp2p.plist";
    default: return NULL;
    }
}

static char *duplicate(const char *text) {
    size_t length = strlen(text);
    char *copy = malloc(length + 1);
    if (copy)
        memcpy(copy, text, length + 1);
    return copy;
}

/* Full path of the client plus the one command line every manager starts. The
 * profile is a fixed system path, so it is safe to place it unquoted; the
 * arguments are deliberately identical to what the old shell controller wrote,
 * which keeps an installed node's unit unchanged across this release. */
static int render(int kind, const char *binary, const char *profile, char *out, size_t length) {
    switch (kind) {
    case FP_SERVICE_SYSTEMD:
        /* ProtectSystem=full rather than the version-dependent strict: full is
         * understood by every systemd, and the client only writes below its own
         * directories and /tmp. */
        return snprintf(out, length,
                        "[Unit]\n"
                        "Description=FastP2P client\n"
                        "After=network-online.target\n"
                        "Wants=network-online.target\n"
                        "\n"
                        "[Service]\n"
                        "User=root\n"
                        "ExecStart=%s run --config %s --background\n"
                        "Restart=always\n"
                        "RestartSec=3\n"
                        "TimeoutStopSec=30\n"
                        "NoNewPrivileges=true\n"
                        "ProtectSystem=full\n"
                        "ProtectHome=true\n"
                        "ReadWriteDirectories=/usr/local/fastp2p /etc/fastp2p /tmp\n"
                        "\n"
                        "[Install]\n"
                        "WantedBy=multi-user.target\n",
                        binary, profile) < (int)length;
    case FP_SERVICE_PROCD:
        return snprintf(out, length,
                        "#!/bin/sh /etc/rc.common\n"
                        "START=95\n"
                        "STOP=10\n"
                        "USE_PROCD=1\n"
                        "start_service() {\n"
                        "    procd_open_instance\n"
                        "    procd_set_param command %s run --config %s --background\n"
                        "    procd_set_param user root\n"
                        "    procd_set_param no_new_privs 1\n"
                        "    procd_set_param respawn 3600 3 0\n"
                        "    procd_set_param stdout 1\n"
                        "    procd_set_param stderr 1\n"
                        "    procd_close_instance\n"
                        "}\n",
                        binary, profile) < (int)length;
    case FP_SERVICE_OPENRC:
        return snprintf(out, length,
                        "#!/sbin/openrc-run\n"
                        "description=\"FastP2P client\"\n"
                        "supervisor=\"supervise-daemon\"\n"
                        "command=\"%s\"\n"
                        "command_args=\"run --config %s --background\"\n"
                        "command_user=\"root:root\"\n"
                        "pidfile=\"/run/fastp2p.pid\"\n"
                        "respawn_delay=3\n"
                        "respawn_max=0\n"
                        "depend() { need net; }\n",
                        binary, profile) < (int)length;
    case FP_SERVICE_LAUNCHD:
        /* No StandardOutPath: --background already redirects the client's own
         * streams to /tmp/fastp2p/fastp2p.log and rotates them. */
        return snprintf(out, length,
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                        "<plist version=\"1.0\">\n"
                        "<dict>\n"
                        "    <key>Label</key><string>top.fastp2p</string>\n"
                        "    <key>ProgramArguments</key>\n"
                        "    <array>\n"
                        "        <string>%s</string><string>run</string>\n"
                        "        <string>--config</string><string>%s</string>"
                        "<string>--background</string>\n"
                        "    </array>\n"
                        "    <key>RunAtLoad</key><true/>\n"
                        "    <key>KeepAlive</key><true/>\n"
                        "</dict>\n"
                        "</plist>\n",
                        binary, profile) < (int)length;
    default:
        return 0;
    }
}

char *fp_service_unit_text(int kind, const char *binary, const char *profile) {
    if (!binary || !*binary || !profile || !*profile)
        return NULL;
    char buffer[UNIT_SPACE];
    if (!render(kind, binary, profile, buffer, sizeof(buffer)))
        return NULL;
    return duplicate(buffer);
}
