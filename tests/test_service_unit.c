/* The client registers itself with the host service manager, so the unit text is the
 * part of installation that breaks silently: a wrong path, a missing --background, or
 * a manager that gets another manager's syntax. Render all four and check the shape
 * each one needs. */

#include "service_unit.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *binary = "/usr/local/fastp2p/fastp2p";
static const char *profile = "/etc/fastp2p/config.conf";

static void check_systemd(void) {
    assert(fp_service_kind("systemd") == FP_SERVICE_SYSTEMD);
    assert(!strcmp(fp_service_name(FP_SERVICE_SYSTEMD), "systemd"));
    assert(!strcmp(fp_service_unit_path(FP_SERVICE_SYSTEMD), "/etc/systemd/system/fastp2p-client.service"));
    char *text = fp_service_unit_text(FP_SERVICE_SYSTEMD, binary, profile);
    assert(text);
    /* The command line has to be exactly the one the client accepts, including the
     * background flag that redirects its own log. */
    assert(strstr(text, "ExecStart=/usr/local/fastp2p/fastp2p run --config /etc/fastp2p/config.conf --background"));
    assert(strstr(text, "Restart=always"));
    assert(strstr(text, "User=root"));
    assert(strstr(text, "WantedBy=multi-user.target"));
    assert(strstr(text, "ReadWriteDirectories=/usr/local/fastp2p /etc/fastp2p /tmp"));
    /* full, never the version-dependent strict: the renderer must not depend on the
     * systemd that happens to be running. */
    assert(strstr(text, "ProtectSystem=full"));
    assert(!strstr(text, "ProtectSystem=strict"));
    free(text);
}

static void check_procd(void) {
    assert(fp_service_kind("procd") == FP_SERVICE_PROCD);
    assert(!strcmp(fp_service_unit_path(FP_SERVICE_PROCD), "/etc/init.d/fastp2p"));
    char *text = fp_service_unit_text(FP_SERVICE_PROCD, binary, profile);
    assert(text);
    assert(strstr(text, "#!/bin/sh /etc/rc.common"));
    assert(strstr(text, "USE_PROCD=1"));
    assert(strstr(text, "procd_set_param command /usr/local/fastp2p/fastp2p run --config /etc/fastp2p/config.conf --background"));
    assert(strstr(text, "procd_set_param respawn 3600 3 0"));
    assert(strstr(text, "procd_set_param user root"));
    free(text);
}

static void check_openrc(void) {
    assert(fp_service_kind("openrc") == FP_SERVICE_OPENRC);
    assert(!strcmp(fp_service_unit_path(FP_SERVICE_OPENRC), "/etc/init.d/fastp2p"));
    char *text = fp_service_unit_text(FP_SERVICE_OPENRC, binary, profile);
    assert(text);
    assert(strstr(text, "#!/sbin/openrc-run"));
    assert(strstr(text, "supervisor=\"supervise-daemon\""));
    assert(strstr(text, "command=\"/usr/local/fastp2p/fastp2p\""));
    assert(strstr(text, "command_args=\"run --config /etc/fastp2p/config.conf --background\""));
    assert(strstr(text, "pidfile=\"/run/fastp2p.pid\""));
    free(text);
}

static void check_launchd(void) {
    assert(fp_service_kind("launchd") == FP_SERVICE_LAUNCHD);
    assert(!strcmp(fp_service_unit_path(FP_SERVICE_LAUNCHD), "/Library/LaunchDaemons/top.fastp2p.plist"));
    char *text = fp_service_unit_text(FP_SERVICE_LAUNCHD, binary, profile);
    assert(text);
    assert(strstr(text, "<key>Label</key><string>top.fastp2p</string>"));
    assert(strstr(text, "<string>/usr/local/fastp2p/fastp2p</string><string>run</string>"));
    assert(strstr(text, "<string>--config</string><string>/etc/fastp2p/config.conf</string><string>--background</string>"));
    assert(strstr(text, "<key>RunAtLoad</key><true/>"));
    assert(strstr(text, "<key>KeepAlive</key><true/>"));
    /* The XML declaration and doctype are what make launchd accept the file. */
    assert(!strncmp(text, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", 39));
    assert(strstr(text, "<!DOCTYPE plist PUBLIC"));
    free(text);
}

int main(void) {
    check_systemd();
    check_procd();
    check_openrc();
    check_launchd();

    /* Unknown input is a programming error, not a reason to write a unit nobody
     * can start: every entry point refuses it. */
    assert(fp_service_kind("upstart") == FP_SERVICE_NONE);
    assert(fp_service_kind("") == FP_SERVICE_NONE);
    assert(!fp_service_kind(NULL));
    assert(!strcmp(fp_service_name(FP_SERVICE_NONE), "none"));
    assert(fp_service_unit_path(FP_SERVICE_NONE) == NULL);
    assert(fp_service_unit_text(FP_SERVICE_NONE, binary, profile) == NULL);
    assert(fp_service_unit_text(FP_SERVICE_SYSTEMD, NULL, profile) == NULL);
    assert(fp_service_unit_text(FP_SERVICE_SYSTEMD, binary, NULL) == NULL);
    assert(fp_service_unit_text(FP_SERVICE_SYSTEMD, "", profile) == NULL);

    /* A path longer than the rendering buffer must not produce a truncated unit that
     * still looks valid. */
    char long_binary[4200];
    memset(long_binary, 'a', sizeof(long_binary) - 1);
    long_binary[sizeof(long_binary) - 1] = 0;
    assert(fp_service_unit_text(FP_SERVICE_SYSTEMD, long_binary, profile) == NULL);

    puts("service-unit: systemd, procd, OpenRC and launchd units render correctly");
    return 0;
}
