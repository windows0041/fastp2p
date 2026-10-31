#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary="$directory/bin/openp2p"
pidfile="$directory/client.pid"
running() {
  [[ -f "$pidfile" ]] || return 1
  pid=$(cat "$pidfile")
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  executable=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
  [[ "$executable" == "$binary" || "$executable" == "$binary (deleted)" ]]
}
case "${1:-status}" in
  start)
    if running; then printf 'Client already running, PID %s\n' "$pid"; exit 0; fi
    set -a
    . "$directory/client.env"
    set +a
    nohup "$binary" -node "$OPENP2P_NODE" -serverhost "$OPENP2P_SERVER" \
      -cacert "$directory/ca.crt" -publicipport "$OPENP2P_PUBLIC_PORT" \
      -sharebandwidth 0 -loglevel 0 -nv > "$directory/client-console.log" 2>&1 </dev/null &
    printf '%s\n' "$!" > "$pidfile"
    sleep 0.5
    if running; then printf 'Started %s, PID %s\n' "$OPENP2P_NODE" "$pid"; else cat "$directory/client-console.log"; exit 1; fi
    ;;
  stop)
    if running; then kill "$pid"; printf 'Stopped client PID %s\n' "$pid"; else printf 'Client is not running\n'; fi
    ;;
  status)
    if running; then printf 'Client running, PID %s\n' "$pid"; else printf 'Client is not running\n'; exit 1; fi
    ;;
  *) printf 'Usage: bash client-control.sh {start|stop|status}\n'; exit 2 ;;
esac
