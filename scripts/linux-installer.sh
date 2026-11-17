#!/bin/sh
# The gateway embeds an architecture manifest and its public download CA.
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
for tool in awk uname od sha256sum mktemp chmod cp stat wc; do
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
cpu=$(uname -m)
# Inspect the running userspace for ambiguous MIPS names; never guess byte order.
elf=/proc/self/exe
[ -r "$elf" ] || elf=/bin/sh
case "$cpu" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    armv7l|armv7|armv8l) arch=armv7 ;;
    i686) arch=i686 ;;
    riscv64) arch=riscv64 ;;
    s390x) arch=s390x ;;
    ppc64le|powerpc64le) arch=ppc64le ;;
    mips64el|mips64le|mips64|mips)
        class=$(od -An -tu1 -j4 -N1 "$elf" | awk '{print $1}')
        endian=$(od -An -tu1 -j5 -N1 "$elf" | awk '{print $1}')
        [ "$class:$endian" = 2:1 ] || fail '当前只提供 MIPS64 小端 64 位用户空间安装包。'
        arch=mips64el ;;
    *) fail "暂不支持 CPU 架构 $cpu，请先提供对应编译包。" ;;
esac
@@FASTP2P_CONTROLLER@@
chmod 700 "$work/fastp2p-service"
# Validate the init implementation and account tools before touching the old app.
"$work/fastp2p-service" check
mkdir -p /var/run
mkdir /var/run/fastp2p-install.lock 2>/dev/null || fail '另一个安装尚未结束；若上次被强制终止，请检查 /var/run/fastp2p-install.lock。'
locked=true
printf '%s\n' "$$" > /var/run/fastp2p-install.lock/pid
@@FASTP2P_DOWNLOAD@@
url=$gateway_url/api/v1/update/download?platform=$package_platform\&version=$expected_version
printf '%s\n' "检测到 $cpu，正在从网关下载 $package_platform $expected_version…"
# Credentials go in a root-private file, not URLs or process command lines.
if command -v curl >/dev/null 2>&1; then
    printf 'header = "Authorization: FastP2P %s"\n' "$token" > "$work/download.conf"
    if [ "$download_ca" -eq 1 ]; then
        printf 'cacert = "%s"\n' "$work/gateway-ca.pem" >> "$work/download.conf"
    fi
    curl -q --config "$work/download.conf" --fail --silent --show-error --noproxy '*' \
        --proto '=https' --connect-timeout 15 --max-time 300 \
        --output "$work/fastp2p" "$url" || fail '下载失败，原服务尚未卸载；请检查网络或重新从控制台下载脚本。'
elif command -v wget >/dev/null 2>&1 && wget --version 2>/dev/null | awk 'NR==1 {gnu=/GNU Wget/} END {exit !gnu}'; then
    printf 'header = Authorization: FastP2P %s\n' "$token" > "$work/download.conf"
    printf 'check_certificate = on\nuse_proxy = off\ndebug = off\nmax_redirect = 0\n' >> "$work/download.conf"
    if [ "$download_ca" -eq 1 ]; then
        printf 'ca_certificate = %s\n' "$work/gateway-ca.pem" >> "$work/download.conf"
    fi
    WGETRC=/dev/null wget --config="$work/download.conf" --quiet --timeout=30 --tries=2 \
        --output-document="$work/fastp2p" "$url" || fail '下载失败，原服务尚未卸载；请检查网络或重新从控制台下载脚本。'
else
    fail '需要 curl 或 GNU wget（启用 TLS）。Debian/Ubuntu: apt install curl；OpenWrt: opkg install curl；Alpine: apk add curl。'
fi
rm -f "$work/download.conf"
[ "$(wc -c < "$work/fastp2p")" -eq "$expected_size" ] || fail '下载长度不符，原服务尚未卸载。'
printf '%s  %s\n' "$expected_sha" "$work/fastp2p" | sha256sum -c - >/dev/null || fail '程序 SHA-256 校验失败，原服务尚未卸载。'
chmod 700 "$work/fastp2p"
version=$("$work/fastp2p" --version) || fail "程序无法在 $cpu 上运行，原服务尚未卸载。"
case "$version" in "fastp2p $expected_version ABI "*) ;; *) fail '安装包版本不符。' ;; esac
[ "$("$work/fastp2p" --installer-abi 2>/dev/null)" = 2 ] || fail '安装需要 fastp2p 客户端 2.0.4 或更新版本。'
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
