#!/bin/sh
# The gateway embeds an architecture manifest and its public download CA.
# Compatible with bash, dash and BusyBox ash.
set -eu
umask 077
fail() { printf '%s\n' "fastp2p: $*" >&2; exit 1; }
sdwan=${FASTP2P_SDWAN:-0}
case "$sdwan" in 0|1) ;; *) fail 'FASTP2P_SDWAN 只能为 0 或 1。' ;; esac
[ "$#" -eq 0 ] || fail '请直接运行 sh 或 bash 加下载文件名，无需传入 Token。'
case "$0" in /*) self=$0 ;; *) self=$PWD/$0 ;; esac
name=${0##*/}
token=''
if [ -z "$token" ]; then
    token=$(printf '%s\n' "$name" | awk -F '[^0-9]+' '
 { for (i=1;i<=NF;i++) if (length($i)==16 && $i ~ /^[1-9][0-9]*$/) { n++; key=$i } }
 END { if(n==1) print key; else exit 1 }') || fail '文件名必须包含且仅包含一个有效的 16 位 Token，请重新从控制台下载。'
fi
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail '需要 root 权限，请以 root 执行此脚本。'
    exec sudo -- env FASTP2P_SDWAN="$sdwan" sh "$self"
fi
for tool in awk uname sha256sum mktemp chmod cp wc; do
    command -v "$tool" >/dev/null 2>&1 || fail "缺少必要命令：$tool"
done
work=$(mktemp -d /tmp/fastp2p-install.XXXXXXXX)
locked=false
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
case "$cpu" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    armv7l|armv7|armv8l) arch=armv7 ;;
    i686) arch=i686 ;;
    riscv64) arch=riscv64 ;;
    s390x) arch=s390x ;;
    ppc64le|powerpc64le) arch=ppc64le ;;
    mips64el|mips64le|mips64|mips)
        # The running shell's ELF header identifies the MIPS userspace ABI.
        command -v dd >/dev/null 2>&1 || fail '检测 MIPS 用户空间需要 dd。'
        elf=/proc/$$/exe
        [ -r "$elf" ] || elf=/bin/sh
        header=$(dd if="$elf" bs=1 count=6 2>/dev/null) || fail '无法读取 MIPS 用户空间的 ELF 头。'
        [ "$header" = "$(printf '\177ELF\002\001')" ] || fail '当前只提供 MIPS64 小端 64 位用户空间安装包。'
        arch=mips64el ;;
    *) fail "暂不支持 CPU 架构 ${cpu}，请先提供对应编译包。" ;;
esac
@@FASTP2P_DOWNLOAD@@
@@FASTP2P_CONTROLLER@@
chmod 700 "$work/fastp2p-service"
# Validate the init implementation and account tools before touching the old app.
"$work/fastp2p-service" check
profile=$("$work/fastp2p-service" profile)
mkdir -p /var/run
mkdir /var/run/fastp2p-install.lock 2>/dev/null || fail '另一个安装尚未结束；若上次被强制终止，请检查 /var/run/fastp2p-install.lock。'
locked=true
printf '%s\n' "$$" > /var/run/fastp2p-install.lock/pid
url=$gateway_url/api/v1/update/download?platform=$package_platform\&version=$expected_version
printf '检测到 %s，正在从网关下载 %s %s…\n' "$cpu" "$package_platform" "$expected_version"
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
[ "$("$work/fastp2p" --service-profile)" = "$profile" ] ||
    fail '安装包使用旧目录，请先同步新版客户端。'
prepared=$profile
if [ ! -e "$profile" ] && [ ! -L "$profile" ]; then
    mkdir "$work/verified"
    prepared=$work/verified/config.conf
    printf '%s' "$token" > "$work/token"
    printf '%s\n' '正在验证网关证书与接入密钥…'
    "$work/fastp2p" install --token-file "$work/token" --config "$prepared" --no-service ||
        fail '网关校验失败。'
    rm -f "$work/token"
fi
unset token
"$work/fastp2p-service" install "$work/fastp2p" "$prepared" ||
    fail '安装未完成，请检查上方错误。'
printf '%s\n' 'fastp2p 安装完成：/usr/local/fastp2p，服务已设置开机启动及异常重启。'
exit 0
