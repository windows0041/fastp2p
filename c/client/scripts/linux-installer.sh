#!/bin/sh
# The gateway prepends the payload digest/size and appends the native ELF.
# Compatible with bash, dash and BusyBox ash. The token lives only in the name.
set -eu
umask 077
fail() { printf '%s\n' "fastp2p: $*" >&2; exit 1; }
[ "$#" -eq 0 ] || fail '请直接运行 sh 或 bash 加下载文件名，无需传入 Token。'
case "$0" in /*) self=$0 ;; *) self=$PWD/$0 ;; esac
name=${0##*/}
token=$(printf '%s\n' "$name" | awk -F '[^0-9]+' '
 { for (i=1;i<=NF;i++) if (length($i)==16 && $i ~ /^[1-9][0-9]*$/) { n++; key=$i } }
 END { if(n==1) print key; else exit 1 }') || fail '文件名必须包含且仅包含一个有效的 16 位 Token，请重新从控制台下载。'
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail '需要 root 权限，请以 root 执行此脚本。'
    exec sudo -- sh "$self"
fi
for tool in awk tail sha256sum mktemp chmod cp stat; do
    command -v "$tool" >/dev/null 2>&1 || fail "缺少必要命令：$tool"
done
work=$(mktemp -d /tmp/fastp2p-install.XXXXXXXX)
locked=false
profile=/var/lib/fastp2p/config/fastp2p.conf
cleanup() {
    status=$?
    set +e
    if $locked; then rm -f /var/run/fastp2p-install.lock/pid; rmdir /var/run/fastp2p-install.lock; fi
    case "$work" in /tmp/fastp2p-install.*) rm -rf -- "$work" ;; esac
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
line=$(awk '/^__FASTP2P_PAYLOAD__$/ { print NR+1; exit }' "$self")
[ -n "$line" ] || fail '安装脚本缺少程序，请重新下载。'
tail -n "+$line" "$self" > "$work/fastp2p"
[ "$(wc -c < "$work/fastp2p")" -eq "$expected_size" ] || fail '程序长度不符，请重新下载。'
printf '%s  %s\n' "$expected_sha" "$work/fastp2p" | sha256sum -c - >/dev/null || fail '程序 SHA-256 校验失败。'
chmod 700 "$work/fastp2p"
version=$("$work/fastp2p" --version) || fail "程序无法在 $(uname -m) 上运行，请选择对应架构的安装脚本。"
case "$version" in 'fastp2p '*" ABI "*) ;; *) fail '安装包不是有效的 fastp2p 程序。' ;; esac
[ "$("$work/fastp2p" --installer-abi 2>/dev/null)" = 1 ] || fail '该安装脚本需要支持配置迁移的 fastp2p 客户端（2.0.4 或更新版本）。'
@@FASTP2P_CONTROLLER@@
chmod 700 "$work/fastp2p-service"
# Validate the init implementation and account tools before touching the old app.
"$work/fastp2p-service" check
mkdir -p /var/run
mkdir /var/run/fastp2p-install.lock 2>/dev/null || fail '另一个安装尚未结束；若上次被强制终止，请检查 /var/run/fastp2p-install.lock。'
locked=true
printf '%s\n' "$$" > /var/run/fastp2p-install.lock/pid
[ ! -L /var/lib/fastp2p ] && [ ! -L /var/lib/fastp2p/config ] || fail '配置目录不能是符号链接。'
mkdir "$work/verified"
prepared=$work/verified/fastp2p.conf
if [ -f "$profile" ]; then
    [ ! -L "$profile" ] || fail '配置不能是符号链接。'
    cp -p "$profile" "$prepared"
elif [ -f /etc/fastp2p/client.json ]; then
    [ ! -L /etc/fastp2p/client.json ] || fail '旧配置不能是符号链接。'
    cp -p /etc/fastp2p/client.json "$prepared"
fi
printf '%s' "$token" > "$work/token"
unset token
printf '%s\n' '正在校验网关证书、接入密钥并保留原节点身份…'
if ! "$work/fastp2p" install --token-file "$work/token" --config "$prepared" --no-service; then
    fail '网关校验未通过，原服务尚未卸载。'
fi
if ! "$work/fastp2p-service" install --binary "$work/fastp2p" --config "$profile" --profile-source "$prepared"; then
    fail '安装未完成，原配置已保留。请查看以上错误后重试。'
fi
printf '%s\n' 'fastp2p 安装完成：/usr/local/fastp2p，服务已设置开机启动及异常重启。'
exit 0
__FASTP2P_PAYLOAD__
