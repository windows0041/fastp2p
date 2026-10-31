#!/usr/bin/env bash
set -euo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dev="${OPENP2P_DEV_DIR:-$HOME/openp2p-dev}"
binary="$dev/bin/openp2p-gateway"
certs="$dev/certs/local"
credentials="$HOME/.config/openp2p-gateway/local.env"
pidfile="$dev/gateway.pid"
mkdir -p "$dev/logs" "$(dirname "$credentials")"

running() {
  [[ -f "$pidfile" ]] || return 1
  pid=$(cat "$pidfile")
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  local executable
  executable=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
  [[ "$executable" == "$binary" || "$executable" == "$binary (deleted)" ]]
}

case "${1:-status}" in
  start)
    if running; then printf 'Gateway is running, PID %s\n' "$pid"; exit 0; fi
    [[ -x "$binary" ]] || { printf 'Build the gateway at %s first.\n' "$binary" >&2; exit 1; }
    if [[ ! -f "$certs/server.crt" ]]; then bash "$project/scripts/generate-cert.sh" "$certs"; fi
    if [[ ! -f "$credentials" ]]; then
      (umask 077; printf 'OPENP2P_USER=localadmin\nOPENP2P_PASSWORD=%s\n' "$(openssl rand -hex 24)" > "$credentials")
    fi
    set -a
    . "$credentials"
    set +a
    nohup "$binary" -bind 127.0.0.1 -cert "$certs/server.crt" -key "$certs/server.key" \
      > "$dev/logs/local-gateway.log" 2>&1 </dev/null &
    printf '%s\n' "$!" > "$pidfile"
    for _ in $(seq 1 40); do
      if curl -fsS --cacert "$certs/ca.crt" https://127.0.0.1:10008/healthz >/dev/null 2>&1; then
        printf 'Gateway ready: https://localhost:10008\nCredentials: %s\nCA certificate: %s/ca.crt\n' "$credentials" "$certs"
        exit 0
      fi
      sleep 0.1
    done
    printf 'Gateway did not become ready; inspect %s/logs/local-gateway.log\n' "$dev" >&2
    exit 1
    ;;
  stop)
    if running; then kill "$pid"; printf 'Stopped gateway PID %s\n' "$pid"; else printf 'Gateway is not running.\n'; fi
    ;;
  status)
    if running; then printf 'Gateway is running, PID %s\n' "$pid"; else printf 'Gateway is not running.\n'; exit 1; fi
    ;;
  *) printf 'Usage: bash scripts/local-gateway.sh {start|stop|status}\n'; exit 2 ;;
esac
