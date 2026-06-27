#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8085}"
LOG_DIR="${LOG_DIR:-./tmp/zlog-complete}"
BASE="http://127.0.0.1:${PORT}"

rm -rf "$LOG_DIR"

go run ./examples/complete -addr ":${PORT}" -log-dir "$LOG_DIR" > /tmp/zlog-complete-example.out 2>&1 &
PID=$!
cleanup() {
  kill -TERM "$PID" >/dev/null 2>&1 || true
  wait "$PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  if curl -fsS "$BASE/_zlog/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

curl -fsS \
  -H 'X-Request-Id: req_demo_001' \
  -H 'X-Correlation-Id: corr_demo_001' \
  -H 'X-User-Id: user_42' \
  -H 'X-Tenant-Id: tenant_np' \
  -H 'baggage: plan=enterprise,tool=sms' \
  "$BASE/api/send-sms?to=%2B9779800000000&message=hello"

echo
sleep 1

echo '--- stats ---'
curl -fsS "$BASE/_zlog/stats"
echo

echo '--- query by request id ---'
go run ./cmd/zlog query --request-id req_demo_001 --sort time --limit 3 "$LOG_DIR/app.ndjson"

echo '--- query by user/service/tool ---'
go run ./cmd/zlog query --user-id user_42 --service sms-api --tool sms_provider_http --sort time --limit 3 "$LOG_DIR/app.ndjson"

echo '--- verify integrity ---'
go run ./cmd/zlog verify --key demo-integrity-key "$LOG_DIR/app.ndjson"
