#!/bin/sh
# Install a root-managed Linux client from a verified executable and profile.
set -eu
umask 077
prefix=/usr/local/fastp2p
binary=$prefix/bin/fastp2p
cli=/usr/local/bin/fastp2p
config_dir=/etc/fastp2p
profile=$config_dir/config.conf
service=fastp2p-client
fail() { printf '%s\n' "fastp2p: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail '服务管理需要 root 权限。'

if [ -f /etc/openwrt_release ] && [ -x /etc/rc.common ]; then
    manager=procd
    unit=/etc/init.d/fastp2p
elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    manager=systemd
    unit=/etc/systemd/system/$service.service
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 && [ -x /sbin/openrc-run ]; then
    manager=openrc
    unit=/etc/init.d/fastp2p
else
    fail '需要运行中的 systemd、OpenWrt procd 或 OpenRC。'
fi

native() {
    case "$manager:$1" in
        systemd:status) systemctl is-active --quiet "$service.service" ;;
        systemd:*) systemctl "$1" "$service.service" ;;
        procd:*) "$unit" "$1" ;;
        openrc:enable) rc-update add fastp2p default ;;
        openrc:disable) rc-update del fastp2p default ;;
        openrc:*) rc-service fastp2p "$1" ;;
    esac
}

write_unit() {
    case "$manager" in
        systemd)
            number=$(systemctl --version | awk 'NR==1 {print $2}')
            protection=full
            case "$number" in ''|*[!0-9]*) ;; *) [ "$number" -lt 232 ] || protection=strict ;; esac
            cat > "$unit" <<EOF
[Unit]
Description=FastP2P client
After=network-online.target
Wants=network-online.target

[Service]
User=root
ExecStart=$binary run --config $profile --background
Restart=always
RestartSec=3
TimeoutStopSec=30
NoNewPrivileges=true
ProtectSystem=$protection
ProtectHome=true
ReadWriteDirectories=$prefix/bin $config_dir /tmp

[Install]
WantedBy=multi-user.target
EOF
            chmod 644 "$unit"
            systemctl daemon-reload ;;
        procd)
            cat > "$unit" <<EOF
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command "$binary" run --config "$profile" --background
    procd_set_param user root
    procd_set_param no_new_privs 1
    procd_set_param respawn 3600 3 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
            chmod 755 "$unit" ;;
        openrc)
            cat > "$unit" <<EOF
#!/sbin/openrc-run
description="FastP2P client"
supervisor="supervise-daemon"
command="$binary"
command_args="run --config $profile --background"
command_user="root:root"
pidfile="/run/fastp2p.pid"
respawn_delay=3
respawn_max=0
depend() { need net; }
EOF
            chmod 755 "$unit" ;;
    esac
}

trusted_directory() {
    [ ! -L "$1" ] && [ -d "$1" ] &&
        ls -ldn "$1" | awk '$3 == 0 && substr($1,6,1) != "w" && substr($1,9,1) != "w" {ok=1} END {exit !ok}'
}

remove_unit() {
    if [ -f "$unit" ]; then
        if native status >/dev/null 2>&1; then native stop; fi
        native disable >/dev/null 2>&1 || true
        rm -f -- "$unit"
        if [ "$manager" = systemd ]; then systemctl daemon-reload; fi
    fi
}

case "${1:-}" in
    check)
        case "${FASTP2P_SDWAN:-0}" in
            0) ;;
            1) command -v ip >/dev/null 2>&1 && [ -c /dev/net/tun ] ||
                fail 'SD-WAN 需要 ip 命令和 /dev/net/tun。' ;;
            *) fail 'FASTP2P_SDWAN 只能为 0 或 1。' ;;
        esac
        [ ! -e "$unit" ] && [ ! -L "$unit" ] || fail '请先卸载已有 FastP2P 服务。'
        if [ -e "$config_dir" ] || [ -L "$config_dir" ]; then
            trusted_directory "$config_dir" || fail '配置目录必须归 root 且禁止其他用户写入。'
        fi
        printf '检测到服务管理器：%s\n' "$manager"
        exit 0 ;;
    profile) printf '%s\n' "$profile"; exit 0 ;;
    start|stop|restart) native "$1"; exit ;;
    install|uninstall) ;;
    *) fail '用法：fastp2p-service install PROGRAM PROFILE | uninstall [--keep-config]' ;;
esac

lock=/var/run/fastp2p-service.lock
mkdir "$lock" 2>/dev/null || fail '另一个服务管理操作尚未结束。'
stage=
config_created=false
installing=false
finish() {
    status=$?
    set +e
    if $installing && [ "$status" -ne 0 ]; then
        remove_unit
        rm -f -- "$binary" "$cli" "$prefix/fastp2p-service"
        if $config_created; then rm -f -- "$profile" "$profile.previous" "$profile.identity" "$profile".ca.*.pem; fi
    fi
    if [ -n "$stage" ]; then
        rm -f -- "$stage/fastp2p" "$stage/controller" "$stage/startup.log"
        rmdir "$stage"
    fi
    if $installing && [ "$status" -ne 0 ]; then
        rmdir "$prefix/bin" "$prefix" "$config_dir" 2>/dev/null
    fi
    rmdir "$lock"
    exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$1" = uninstall ]; then
    case "$#:${2:-}" in 1:|2:--keep-config) ;; *) fail '卸载参数无效。' ;; esac
    trusted_directory "$prefix" && trusted_directory "$prefix/bin" || fail '程序目录权限无效。'
    if [ -e "$config_dir" ] || [ -L "$config_dir" ]; then
        trusted_directory "$config_dir" || fail '配置目录权限无效。'
    fi
    remove_unit
    rm -f -- "$binary" "$binary.old" "$cli" "$prefix/fastp2p-service"
    if [ "${2:-}" != --keep-config ]; then
        rm -f -- "$profile" "$profile.previous" "$profile.identity" "$profile".ca.*.pem
        rmdir "$config_dir" 2>/dev/null || true
    fi
    if trusted_directory /tmp/fastp2p; then
        rm -f -- /tmp/fastp2p/fastp2p.log
        rmdir /tmp/fastp2p 2>/dev/null || true
    fi
    rmdir "$prefix/bin" "$prefix" 2>/dev/null || true
    printf '%s\n' 'FastP2P 已卸载。'
    exit 0
fi

[ "$#" -eq 3 ] && [ -f "$2" ] && [ -f "$3" ] && [ ! -L "$3" ] || fail '缺少已校验的程序或配置。'
"$0" check >/dev/null
[ "$("$2" --service-profile)" = "$profile" ] || fail '客户端和安装器的配置路径不一致。'
if [ "${FASTP2P_SDWAN:-0}" -eq 1 ]; then "$2" --check-sdwan; fi
trusted_directory /usr/local || fail '/usr/local 必须归 root 且禁止其他用户写入。'
for path in "$prefix" "$prefix/bin" "$config_dir"; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then mkdir -m 755 "$path"; fi
    trusted_directory "$path" || fail "目录权限无效：$path"
done
mkdir -p /usr/local/bin
trusted_directory /usr/local/bin || fail '/usr/local/bin 权限无效。'
[ ! -e "$binary" ] && [ ! -L "$binary" ] && [ ! -e "$cli" ] && [ ! -L "$cli" ] ||
    fail '请先卸载已有 FastP2P 程序。'
if [ "$3" != "$profile" ]; then
    [ ! -e "$profile" ] && [ ! -L "$profile" ] || fail '配置路径已被占用。'
fi
stage=$(mktemp -d "$prefix/.install.XXXXXXXX")
cp "$2" "$stage/fastp2p" && chmod 755 "$stage/fastp2p" ||
    fail '暂存程序失败，请检查 /usr/local 的可用空间。'
installing=true
if [ "$3" != "$profile" ]; then
    config_created=true
    "$stage/fastp2p" --relocate-profile "$3" "$profile"
fi
"$stage/fastp2p" run --config "$profile" --verify-start > "$stage/startup.log" 2>&1 || {
    cat "$stage/startup.log" >&2
    fail '客户端启动检查失败。'
}
mv "$stage/fastp2p" "$binary"
ln -s "$binary" "$cli"
if [ "$manager" != procd ]; then
    cp "$0" "$stage/controller"
    chmod 755 "$stage/controller"
    mv "$stage/controller" "$prefix/fastp2p-service"
fi
write_unit
native enable
native start
for check in 1 2 3; do sleep 1; native status >/dev/null 2>&1 || fail '客户端服务未持续运行。'; done
installing=false
printf 'FastP2P 已安装，配置 %s，日志 /tmp/fastp2p/fastp2p.log。\n' "$profile"
