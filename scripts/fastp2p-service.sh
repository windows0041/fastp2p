#!/bin/sh
# OS integration is deliberately kept outside the C P2P program.
set -eu
umask 077
prefix=/usr/local/fastp2p
binary=$prefix/bin/fastp2p
service=fastp2p-client
fail() { printf '%s\n' "fastp2p: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail '服务管理需要 root 权限。'
detect_init() {
    if [ -f /etc/openwrt_release ] && [ -x /etc/rc.common ]; then
        printf procd
    elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        printf systemd
    elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 && [ -x /sbin/openrc-run ]; then
        printf openrc
    else
        fail '没有检测到运行中的 systemd、OpenWrt procd 或 OpenRC；请在宿主机安装，或由容器的重启策略管理前台进程。'
    fi
}
manager=$(detect_init)
parent=/var/lib/fastp2p
if [ "$manager" = procd ]; then parent=/etc/fastp2p-client; fi
state=$parent/config
profile=$state/fastp2p.conf
transaction=false
locked=false
install_backup=
phase=
discard_install_stage() {
    if [ -n "$install_backup" ]; then
        rm -f -- "$install_backup/incoming" "$install_backup/runtime.new" \
            "$install_backup/cli.new" "$install_backup/controller.new"
    fi
}
finish() {
    status=$?
    set +e
    if [ "$status" -ne 0 ]; then
        if $transaction; then
            printf 'fastp2p: %s失败（状态 %s），正在回滚。\n' "$phase" "$status" >&2
            rollback
        elif [ -n "$install_backup" ]; then
            rm -f -- "$install_backup/runtime" "$install_backup/cli" "$install_backup/controller"
        fi
    fi
    discard_install_stage
    if $locked; then rm -f /var/run/fastp2p-service.lock/pid; rmdir /var/run/fastp2p-service.lock; fi
    exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
case "${1:-}" in
    check|profile) ;;
    *)
        mkdir -p /var/run
        mkdir /var/run/fastp2p-service.lock 2>/dev/null || fail '另一个服务管理操作尚未结束；若上次被强制终止，请检查 /var/run/fastp2p-service.lock。'
        locked=true
        printf '%s\n' "$$" > /var/run/fastp2p-service.lock/pid ;;
esac
account_ready() {
    if id fastp2p >/dev/null 2>&1; then
        [ "$(id -u fastp2p)" -ne 0 ] || fail 'fastp2p 用户不能使用 UID 0。'
        return
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "$state" --shell /bin/false fastp2p
    elif [ "$manager" = procd ] && [ -f /lib/functions.sh ]; then
        # OpenWrt's own locked passwd/group helpers also work without adduser.
        ( set +u; . /lib/functions.sh
          gid=$(group_add_next fastp2p)
          user_add fastp2p '' "$gid" fastp2p "$state" /bin/false )
    elif command -v adduser >/dev/null 2>&1 && command -v addgroup >/dev/null 2>&1; then
        addgroup -S fastp2p
        adduser -S -D -H -h "$state" -s /bin/false -G fastp2p fastp2p
    else
        fail '缺少系统用户管理工具，请安装 shadow/useradd 或 BusyBox adduser 后重试。'
    fi
    id fastp2p >/dev/null 2>&1 || fail '无法创建 fastp2p 服务用户。'
}
start_service() {
    case "$manager" in
        systemd) systemctl start "$service.service" ;;
        procd) /etc/init.d/fastp2p start ;;
        openrc) rc-service fastp2p start ;;
    esac
}
service_running() {
    case "$manager" in
        systemd) systemctl is-active --quiet "$service.service" ;;
        procd) /etc/init.d/fastp2p status ;;
        openrc) rc-service fastp2p status ;;
    esac
}
service_enabled() {
    case "$manager" in
        systemd) systemctl is-enabled --quiet "$service.service" ;;
        procd) /etc/init.d/fastp2p enabled ;;
        openrc) rc-update show default | awk '$1 == "fastp2p" { found=1 } END { exit !found }' ;;
    esac
}
enable_service() {
    case "$manager" in
        systemd) systemctl enable "$service.service" ;;
        procd) /etc/init.d/fastp2p enable ;;
        openrc) rc-update add fastp2p default ;;
    esac
}
disable_service() {
    case "$manager" in
        systemd) systemctl disable "$service.service" ;;
        procd) if [ -x /etc/init.d/fastp2p ]; then /etc/init.d/fastp2p disable; fi ;;
        openrc) rc-update del fastp2p default ;;
    esac
}
stop_service() {
    case "$manager" in
        systemd)
            if systemctl cat "$service.service" >/dev/null 2>&1; then systemctl stop "$service.service"; fi ;;
        procd) if [ -x /etc/init.d/fastp2p ]; then /etc/init.d/fastp2p stop; fi ;;
        openrc) if [ -f /etc/init.d/fastp2p ]; then rc-service fastp2p stop; fi ;;
    esac
}
remove_service() {
    stop_service
    case "$manager" in
        systemd)
            if [ -e "/etc/systemd/system/$service.service" ]; then
                systemctl disable "$service.service"
                rm -f "/etc/systemd/system/$service.service"
            fi
            # A legacy migration override must not redirect the replacement unit.
            rm -f "/etc/systemd/system/$service.service.d/20-remote-upgrade.conf"
            systemctl daemon-reload ;;
        procd) if [ -x /etc/init.d/fastp2p ]; then /etc/init.d/fastp2p disable; rm -f /etc/init.d/fastp2p; fi ;;
        openrc) if [ -f /etc/init.d/fastp2p ]; then rc-update del fastp2p default; rm -f /etc/init.d/fastp2p; fi ;;
    esac
}
write_service() {
    group=$(id -gn fastp2p)
    case "$manager" in
        systemd)
            protection=full
            number=$(systemctl --version | awk 'NR==1 { print $2 }')
            case "$number" in *[!0-9]*|'') ;; *) if [ "$number" -ge 232 ]; then protection=strict; fi ;; esac
            mkdir -p /etc/systemd/system
            cat > "/etc/systemd/system/$service.service" <<EOF
[Unit]
Description=fastp2p client
After=network-online.target
Wants=network-online.target
StartLimitInterval=0
[Service]
User=fastp2p
Group=$group
ExecStart=$binary run --config $profile
Restart=always
RestartSec=3
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=$protection
ProtectHome=true
ReadWriteDirectories=$prefix/bin $state
[Install]
WantedBy=multi-user.target
EOF
            chmod 644 "/etc/systemd/system/$service.service"
            systemctl daemon-reload
            systemctl enable "$service.service" ;;
        procd)
            cat > /etc/init.d/fastp2p <<EOF
#!/bin/sh /etc/rc.common
# fastp2p managed service
START=95
STOP=10
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command "$binary" run --config "$profile"
    procd_set_param user fastp2p
    procd_set_param no_new_privs 1
    procd_set_param respawn 3600 3 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
            chmod 755 /etc/init.d/fastp2p
            /etc/init.d/fastp2p enable ;;
        openrc)
            cat > /etc/init.d/fastp2p <<EOF
#!/sbin/openrc-run
# fastp2p managed service
description="fastp2p client"
supervisor="supervise-daemon"
command="$binary"
command_args="run --config $profile"
command_user="fastp2p:$group"
pidfile="/run/fastp2p.pid"
respawn_delay=3
respawn_max=0
depend() { need net; }
EOF
            chmod 755 /etc/init.d/fastp2p
            rc-update add fastp2p default ;;
    esac
}
file_metadata() {
    if info=$(stat -c '%u:%g:%a:%h' -- "$1" 2>/dev/null) ||
       info=$(busybox stat -c '%u:%g:%a:%h' -- "$1" 2>/dev/null); then
        printf '%s\n' "$info"
        return
    fi
    # Minimal OpenWrt images may have no stat applet. Read numeric metadata
    # from the first record only, since the filename may contain a newline.
    info=$(LC_ALL=C ls -ldn -- "$1" 2>/dev/null) || return 1
    printf '%s\n' "$info" | LC_ALL=C awk '
        function permissions(at, x) {
            x=substr($1,at+2,1)
            return 4*(substr($1,at,1)=="r") + 2*(substr($1,at+1,1)=="w") + (x ~ /[xst]/)
        }
        NR==1 && $1 ~ /^[-d][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-][+.@]?$/ &&
                 $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {
            special=4*(substr($1,4,1) ~ /[sS]/) + 2*(substr($1,7,1) ~ /[sS]/) + (substr($1,10,1) ~ /[tT]/)
            mode=512*special + 64*permissions(2) + 8*permissions(5) + permissions(8)
            printf "%s:%s:%o:%s\n", $3, $4, mode, $2
            valid=1
        }
        END {exit !valid}'
}
is_single_link_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    details=$(file_metadata "$1") || return 1
    [ "${details##*:}" = 1 ]
}
prune_program_backups() {
    # Only installer-owned directories and exact program filenames. Keep the
    # saved profiles, certificates and diagnostic logs; never traverse links.
    cleanup_pending=false
    for cleanup_dir in "$prefix/.backups/"*; do
        [ -d "$cleanup_dir" ] && [ ! -L "$cleanup_dir" ] || continue
        printf '%s\n' "${cleanup_dir##*/}" | grep -Eq '^[0-9]{8}T[0-9]{6}\.[0-9]+$' || continue
        details=$(file_metadata "$cleanup_dir") || continue
        [ "${details%:*}" = 0:0:700 ] || continue
        for cleanup_name in "$@"; do
            cleanup_file=$cleanup_dir/$cleanup_name
            if [ -f "$cleanup_file" ] || [ -L "$cleanup_file" ]; then
                rm -f -- "$cleanup_file" || cleanup_pending=true
            fi
        done
    done
    if $cleanup_pending; then printf '%s\n' '部分安装临时文件未能清理，请检查文件权限。' >&2; fi
    return 0
}
save_program() {
    if [ -L "$1" ]; then
        cp -pP -- "$1" "$2"
    elif [ -f "$1" ]; then
        ln -- "$1" "$2" 2>/dev/null || cp -p -- "$1" "$2"
    fi
}
restore_program() {
    if [ -f "$1" ] || [ -L "$1" ]; then
        if [ ! -L "$1" ] && [ ! -L "$2" ] && [ "$1" -ef "$2" ]; then
            rm -f -- "$1"
        else
            mv -fT -- "$1" "$2"
        fi
    else
        rm -f -- "$2"
    fi
}
install_service() {
    source_binary=
    source_profile=$profile
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --binary) [ "$#" -ge 2 ] || fail '缺少程序路径。'; source_binary=$2; shift 2 ;;
            --config) [ "$#" -ge 2 ] && [ "$2" = "$profile" ] || fail '服务配置路径无效。'; shift 2 ;;
            --profile-source) [ "$#" -ge 2 ] || fail '缺少已校验配置路径。'; source_profile=$2; shift 2 ;;
            *) fail '未知服务安装参数。' ;;
        esac
    done
    [ -f "$source_binary" ] || fail '找不到已校验的客户端程序。'
    [ -f "$source_profile" ] && [ ! -L "$source_profile" ] || fail '找不到已校验的客户端配置。'
    [ ! -L "$state" ] && [ ! -L "$profile" ] || fail '配置路径不能是符号链接。'
    account_ready
    [ ! -L "$parent" ] || fail '数据目录不能是符号链接。'
    parent_metadata=
    config_metadata=
    if [ -e "$parent" ]; then
        [ -d "$parent" ] || fail '数据路径不是目录。'
        details=$(file_metadata "$parent") || fail '无法读取数据目录的权限。'
        parent_metadata=${details%:*}
        parent_uid=${parent_metadata%%:*}
        [ "$parent_uid" -eq 0 ] || [ "$parent_uid" -eq "$(id -u fastp2p)" ] || fail '数据目录属于其他用户，未卸载原服务。'
        if [ "$parent_uid" -ne 0 ]; then
            # An old co-located gateway may still need to write this directory.
            # Never take it away from a running gateway during client migration.
            if [ "$manager" = systemd ]; then
                for unit in fastp2p-gateway fastp2p-c-gateway openp2p-c-gateway; do
                    if systemctl is-active --quiet "$unit.service"; then fail '请先迁移使用旧数据目录的网关，再升级客户端。'; fi
                done
            fi
            if command -v pidof >/dev/null 2>&1; then
                for process in fastp2p-gateway fastp2p-c-gateway openp2p-c-gateway; do
                    if pidof "$process" >/dev/null 2>&1; then fail '检测到运行中的旧网关，请先迁移网关数据目录。'; fi
                done
            fi
        fi
    fi
    if [ -e "$state" ]; then
        [ -d "$state" ] || fail '配置路径不是目录。'
        details=$(file_metadata "$state") || fail '无法读取配置目录的权限。'
        config_metadata=${details%:*}
    fi
    [ ! -L "$prefix" ] || fail '安装目录不能是符号链接。'
    mkdir -p "$prefix"
    chown 0:0 "$prefix"; chmod 755 "$prefix"
    [ ! -L "$prefix/.backups" ] || fail '备份目录不能是符号链接。'
    mkdir -p "$prefix/.backups"; chown 0:0 "$prefix/.backups"; chmod 700 "$prefix/.backups"
    # A previous failed install may have left its incoming image and partial
    # replacements on disk. Older verified backups and profiles are separate.
    prune_program_backups incoming runtime.new cli.new controller.new
    backup=$prefix/.backups/$(date +%Y%m%dT%H%M%S).$$
    mkdir "$backup"; chmod 700 "$backup"
    install_backup=$backup
    # Both destinations use the same root-owned image on a single filesystem.
    # A hard link keeps the CLI pinned even after the service swaps its path.
    if ! cp "$source_binary" "$backup/incoming"; then
        bytes=$(wc -c < "$source_binary")
        fail "无法暂存客户端（需 $bytes 字节），请检查 /usr/local 的磁盘空间。原服务尚未停止。"
    fi
    chmod 755 "$backup/incoming"
    save_program "$backup/incoming" "$backup/runtime.new"
    save_program "$backup/incoming" "$backup/cli.new"
    cp "$0" "$backup/controller.new"; chmod 755 "$backup/controller.new"
    cp "$source_profile" "$backup/desired-config"; chmod 600 "$backup/desired-config"
    save_program "$binary" "$backup/runtime"
    save_program /usr/local/bin/fastp2p "$backup/cli"
    save_program "$prefix/fastp2p-service" "$backup/controller"
    if [ -f /etc/fastp2p/client.json ]; then
        cp -p /etc/fastp2p/client.json "$backup/legacy-profile.json"
        for ca in /etc/fastp2p/client.json.ca.*.pem; do
            [ ! -f "$ca" ] || cp -p "$ca" "$backup/${ca##*/}"
        done
    fi
    if [ -f "/etc/systemd/system/$service.service" ]; then cp -p "/etc/systemd/system/$service.service" "$backup/unit"; fi
    if [ -d "/etc/systemd/system/$service.service.d" ]; then cp -a "/etc/systemd/system/$service.service.d" "$backup/dropins"; fi
    if [ -f /etc/init.d/fastp2p ]; then cp -p /etc/init.d/fastp2p "$backup/init"; fi
    old_service=false
    case "$manager" in
        systemd) if systemctl cat "$service.service" >/dev/null 2>&1; then old_service=true; fi ;;
        *) if [ -f /etc/init.d/fastp2p ]; then old_service=true; fi ;;
    esac
    old_enabled=false
    if $old_service && service_enabled >/dev/null 2>&1; then old_enabled=true; fi
    config_changed=false
    parent_changed=false
    restore_metadata() {
        target=$1; metadata=$2
        if [ -n "$metadata" ]; then
            owner=${metadata%:*}; mode=${metadata##*:}
            chown -h "$owner" "$target"; chmod "$mode" "$target"
        else rmdir "$target" 2>/dev/null || true; fi
    }
    rollback() {
        stop_service >/dev/null 2>&1 || true
        # Remove the replacement's boot links, including fresh-install failures.
        # Restoring an init file alone does not restore procd/OpenRC autostart.
        disable_service >/dev/null 2>&1 || true
        restore_program "$backup/runtime" "$binary"
        restore_program "$backup/cli" /usr/local/bin/fastp2p
        restore_program "$backup/controller" "$prefix/fastp2p-service"
        discard_install_stage
        if $config_changed; then
            chown -h 0:0 "$state"; chmod 700 "$state"
            rm -f "$profile" "$profile.previous" "$profile.identity" "$state"/fastp2p.conf.ca.*.pem
            for saved in "$backup/config/"*; do
                [ ! -f "$saved" ] || cp -p "$saved" "$state/${saved##*/}"
            done
        fi
        case "$manager" in
            systemd)
                if [ -f "$backup/unit" ]; then cp -p "$backup/unit" "/etc/systemd/system/$service.service"; else rm -f "/etc/systemd/system/$service.service"; fi
                if [ -d "$backup/dropins" ]; then mkdir -p "/etc/systemd/system/$service.service.d"; cp -a "$backup/dropins/." "/etc/systemd/system/$service.service.d/"; fi
                systemctl daemon-reload >/dev/null 2>&1 || true ;;
            *) if [ -f "$backup/init" ]; then cp -p "$backup/init" /etc/init.d/fastp2p; else rm -f /etc/init.d/fastp2p; fi ;;
        esac
        if $parent_changed; then
            restore_metadata "$state" "$config_metadata"
            restore_metadata "$parent" "$parent_metadata"
        fi
        if $old_enabled; then enable_service >/dev/null 2>&1 || true; fi
        if $old_service; then start_service >/dev/null 2>&1 || true; fi
    }
    phase=停止旧服务
    transaction=true
    printf '%s\n' "服务管理方式：$manager；正在探测并卸载旧服务，保留配置。"
    remove_service
    phase=准备安装与配置目录
    group=$(id -gn fastp2p)
    [ ! -L "$prefix/bin" ] && [ ! -L "$parent" ] && [ ! -L "$state" ] || return 1
    mkdir -p "$prefix/bin" "$parent" /usr/local/bin
    # Stop StateDirectory users before changing ownership: systemd may chown it
    # again on restart. Only the config child is writable by the new client.
    parent_changed=true
    chown -h 0:0 "$parent"; chmod 711 "$parent"
    mkdir -p "$state"
    chown -h 0:0 "$state"
    [ -d "$state" ] && [ ! -L "$state" ] || fail '配置目录在迁移时发生变化。'
    chmod 700 "$state"
    mkdir "$backup/config"
    for file in "$profile" "$profile.previous" "$profile.identity" "$state"/fastp2p.conf.ca.*.pem; do
        if [ -e "$file" ] || [ -L "$file" ]; then
            is_single_link_file "$file" || fail '无法确认配置是单链接普通文件。'
            cp -p "$file" "$backup/config/${file##*/}"
        fi
    done
    config_changed=true
    phase=更新程序文件
    chown "fastp2p:$group" "$prefix/bin"; chmod 700 "$prefix/bin"
    mv -fT "$backup/runtime.new" "$binary"
    mv -fT "$backup/cli.new" /usr/local/bin/fastp2p
    mv -fT "$backup/controller.new" "$prefix/fastp2p-service"
    phase=写入配置及证书
    "$backup/incoming" --relocate-profile "$backup/desired-config" "$profile"
    chown "fastp2p:$group" "$profile"; chmod 600 "$profile"
    for ca in "$state"/fastp2p.conf.ca.*.pem; do
        [ -f "$ca" ] || continue
        is_single_link_file "$ca" || fail '无法确认证书是单链接普通文件。'
        chown "0:$group" "$ca"; chmod 640 "$ca"
    done
    chown "fastp2p:$group" "$state"; chmod 700 "$state"
    # Pure schema checks cannot detect occupied ports or account permissions.
    # Probe the full runtime as the service account before committing the upgrade.
    phase=客户端启动检查
    if ! "$backup/incoming" run --config "$profile" --verify-start > "$backup/startup-check.log" 2>&1; then
        fail "客户端启动检查失败，正在恢复旧服务。诊断日志：$backup/startup-check.log"
    fi
    phase=注册开机启动服务
    write_service
    phase=启动客户端服务
    start_service
    # Native init start commands may succeed before the child actually starts.
    # Catch an immediate exit/crash while rollback files are still authoritative.
    for check in 1 2 3; do
        sleep 1
        service_running >/dev/null 2>&1 || fail '客户端服务未持续运行，正在恢复旧服务。'
    done
    printf '%s\n' "$manager" > "$prefix/init"
    transaction=false
    prune_program_backups incoming runtime cli controller legacy-runtime legacy-runtime.old \
        runtime.restore cli.restore controller.restore runtime.new cli.new controller.new
    rm -f -- "$binary.old" || printf '%s\n' '服务已安装，但旧程序未能删除。' >&2
    rm -f /var/lib/fastp2p-client/fastp2p /var/lib/fastp2p-client/fastp2p.old
    rmdir /var/lib/fastp2p-client 2>/dev/null || true
    rm -f /etc/fastp2p/client.json /etc/fastp2p/client.json.identity /etc/fastp2p/client.json.ca.*.pem
    printf '%s\n' "服务安装完成，旧程序已清理；配置和诊断备份：$backup"
}
case "${1:-}" in
    check)
        mv --help 2>&1 | grep -q -- '-T' || fail '需要支持 -T 的 mv（GNU coreutils 或 BusyBox）。'
        file_metadata / >/dev/null || fail '无法读取文件权限，请检查 stat 或 ls -ldn。'
        if [ "$manager" = procd ]; then
            distribution=$(awk -F= '
                /^DISTRIB_ID=/ {gsub(/[^A-Za-z0-9_.-]/,"",$2); id=$2}
                /^DISTRIB_RELEASE=/ {gsub(/[^A-Za-z0-9_.-]/,"",$2); version=$2}
                END {printf "%s%s%s", id?id:"OpenWrt", version?" ":"", version}
            ' /etc/openwrt_release)
            printf '%s\n' "检测到系统：$distribution（procd）"
        else
            printf '%s\n' "检测到服务管理器：$manager"
        fi ;;
    profile) printf '%s\n' "$profile" ;;
    install) install_service "$@" ;;
    stop) stop_service ;;
    start) start_service ;;
    restart) stop_service; start_service ;;
    uninstall)
        case "$#:${2:-}" in 1:|2:--keep-config) ;; *) fail '卸载参数无效。' ;; esac
        remove_service
        if [ "${2:-}" != --keep-config ]; then
            rm -f "$binary" "$binary.old" /usr/local/bin/fastp2p "$prefix/fastp2p-service"
            rm -f "$profile" "$profile.previous" "$profile.identity" "$state"/fastp2p.conf.ca.*.pem
            # Only this root-owned, installer-created backup directory is purged.
            if [ -d "$prefix/.backups" ] && [ ! -L "$prefix/.backups" ]; then rm -rf -- "$prefix/.backups"; fi
            rmdir "$prefix/bin" "$state" "$parent" 2>/dev/null || true
            rm -f "$prefix/init"; rmdir "$prefix" 2>/dev/null || true
        fi
        printf '%s\n' '旧服务已卸载。' ;;
    *) fail '用法：fastp2p-service install|uninstall [--keep-config]|start|stop|restart|check' ;;
esac
