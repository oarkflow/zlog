#!/usr/bin/env bash
set -euo pipefail
PORT="${PORT:-8090}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

go run ./examples/observability -addr ":${PORT}" > /tmp/zlog-observability-example.log 2>&1 &
PID=$!
cleanup() { kill "$PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for i in {1..40}; do
  if curl -fsS "http://localhost:${PORT}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.25
done

sleep 3

echo "== overview =="
curl -fsS "http://localhost:${PORT}/api/v1/overview" | head -c 600; echo

echo "== services =="
curl -fsS "http://localhost:${PORT}/api/v1/services" | head -c 600; echo

echo "== logs =="
curl -fsS "http://localhost:${PORT}/api/v1/logs?service=api-gateway&limit=3&desc=true" | head -c 800; echo

echo "== spans =="
curl -fsS "http://localhost:${PORT}/api/v1/spans?sort=duration&desc=true&limit=3" | head -c 800; echo

echo "== metrics =="
curl -fsS "http://localhost:${PORT}/api/v1/metrics?name=cpu_usage_percent&limit=3&desc=true" | head -c 800; echo

echo "Dashboard: http://localhost:${PORT}"
