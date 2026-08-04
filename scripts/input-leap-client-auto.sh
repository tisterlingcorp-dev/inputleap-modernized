#!/usr/bin/env bash
# Resolve the local Windows peer by stable name before starting Input Leap.
# The client itself keeps the hostname so it can resolve it again after a
# network change and during its normal reconnect loop.
set -u

CLIENT="${INPUTLEAP_CLIENT:-$HOME/input-leapc}"
SCREEN_NAME="${INPUTLEAP_SCREEN:-input-leap-client}"
PORT="${INPUTLEAP_PORT:-24800}"
LOG_FILE="${INPUTLEAP_LOG:-$HOME/input-leap-client.log}"
SERVER_NAMES=("${INPUTLEAP_SERVER:-input-leap-server.local}" "input-leap-server")

resolve_name() {
    local name ip
    for name in "${SERVER_NAMES[@]}"; do
        ip=""
        while read -r ip _; do
            if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                printf '%s\n' "$name"
                return 0
            fi
        done < <(getent ahostsv4 "$name" 2>/dev/null || true)
    done
    return 1
}

mkdir -p "$(dirname "$LOG_FILE")"

while true; do
    if server_name="$(resolve_name)"; then
        printf '[%s] resolved local server as %s\n' "$(date --iso-8601=seconds)" "$server_name" >>"$LOG_FILE"
        "$CLIENT" \
            --use-x11 \
            --display :0 \
            --name "$SCREEN_NAME" \
            --enable-crypto \
            --enable-drag-drop \
            --no-daemon \
            --debug DEBUG \
            "$server_name:$PORT" >>"$LOG_FILE" 2>&1
        status=$?
        printf '[%s] client exited with status %s; retrying\n' "$(date --iso-8601=seconds)" "$status" >>"$LOG_FILE"
        sleep 3
    else
        printf '[%s] local server not resolved; retrying\n' "$(date --iso-8601=seconds)" >>"$LOG_FILE"
        sleep 5
    fi
done
