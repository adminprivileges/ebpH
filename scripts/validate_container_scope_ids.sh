#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <container_a> <container_b>" >&2
  exit 2
fi

C1="$1"
C2="$2"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 2
fi
if ! command -v ebph >/dev/null 2>&1; then
  echo "ebph CLI is required" >&2
  exit 2
fi

spawn_sleep() {
  local container="$1"
  sudo docker exec -d "$container" /bin/sh -lc 'sleep 60' >/dev/null
}

latest_sleep_pid() {
  local container="$1"
  sudo docker top "$container" -eo pid,args | awk '/sleep 60/{pid=$1} END{if (pid) print pid}'
}

pid_scope() {
  local pid="$1"
  sudo ebph ps -t | awk -v pid="$pid" '$1==pid {print $3; found=1} END{if(!found) exit 1}'
}

echo "[1/4] Spawning two short-lived workload processes in each container..."
spawn_sleep "$C1"
spawn_sleep "$C1"
spawn_sleep "$C2"
spawn_sleep "$C2"
sleep 1

P1A="$(latest_sleep_pid "$C1")"
P1B="$(sudo docker top "$C1" -eo pid,args | awk '/sleep 60/{print $1}' | head -n1)"
P2A="$(latest_sleep_pid "$C2")"
P2B="$(sudo docker top "$C2" -eo pid,args | awk '/sleep 60/{print $1}' | head -n1)"

if [[ -z "$P1A" || -z "$P1B" || -z "$P2A" || -z "$P2B" ]]; then
  echo "Could not discover sleep PIDs in one or both containers." >&2
  exit 1
fi

echo "[2/4] Resolving ebph scopes from ebph ps -t ..."
# Container scope IDs are synced periodically in userspace; allow brief retry
# window to avoid transient mixed host/container scope readings.
for _attempt in $(seq 1 10); do
  S1A="$(pid_scope "$P1A")"
  S1B="$(pid_scope "$P1B")"
  S2A="$(pid_scope "$P2A")"
  S2B="$(pid_scope "$P2B")"

  if [[ "$S1A" == "$S1B" && "$S2A" == "$S2B" && "$S1A" != "$S2A" ]]; then
    break
  fi
  sleep 1
done

echo "Container $C1 PIDs $P1A/$P1B => scopes $S1A/$S1B"
echo "Container $C2 PIDs $P2A/$P2B => scopes $S2A/$S2B"

echo "[3/4] Verifying per-container consistency..."
if [[ "$S1A" != "$S1B" ]]; then
  echo "FAIL: $C1 processes do not share one scope id." >&2
  exit 1
fi
if [[ "$S2A" != "$S2B" ]]; then
  echo "FAIL: $C2 processes do not share one scope id." >&2
  exit 1
fi

echo "[4/4] Verifying cross-container separation..."
if [[ "$S1A" == "$S2A" ]]; then
  echo "FAIL: $C1 and $C2 ended up with the same scope id ($S1A)." >&2
  exit 1
fi

echo "[extra] Verifying host process scope is 0 in container mode..."
/usr/bin/sleep 60 &
HOST_SLEEP_PID=$!
sleep 1
HOST_SCOPE="$(pid_scope "$HOST_SLEEP_PID")"
if [[ "$HOST_SCOPE" != "0" ]]; then
  echo "FAIL: host sleep pid $HOST_SLEEP_PID has scope $HOST_SCOPE (expected 0)." >&2
  kill "$HOST_SLEEP_PID" >/dev/null 2>&1 || true
  exit 1
fi

echo "[extra] Verifying host/container same executable split by scope..."
SLEEP_SCOPES="$(sudo ebph ps -p | awk '$1=="sleep" || $1=="/usr/bin/sleep" {print $2}')"
if ! printf '%s\n' "$SLEEP_SCOPES" | grep -qx "0"; then
  echo "FAIL: did not find sleep profile with host scope 0." >&2
  kill "$HOST_SLEEP_PID" >/dev/null 2>&1 || true
  exit 1
fi
if ! printf '%s\n' "$SLEEP_SCOPES" | grep -qx "$S1A"; then
  echo "FAIL: did not find sleep profile with container scope $S1A." >&2
  kill "$HOST_SLEEP_PID" >/dev/null 2>&1 || true
  exit 1
fi

kill "$HOST_SLEEP_PID" >/dev/null 2>&1 || true

echo "PASS: different containers have different scope IDs, and processes within each container share that container's scope ID."
