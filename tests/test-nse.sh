#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT_PATH=${SCRIPT_PATH:-"$ROOT_DIR/nmap/http-vuln-php2shell.nse"}
SERVER_PATH="$ROOT_DIR/tests/mock_php_server.py"
NMAP_BIN=${NMAP_BIN:-nmap}
PORT=${PORT:-18080}

SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

python3 "$SERVER_PATH" --port "$PORT" &
SERVER_PID=$!

for _ in {1..50}; do
  if curl --silent --fail "http://127.0.0.1:$PORT/none" >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$PORT/none" >/dev/null

scan() {
  local path=$1
  "$NMAP_BIN" -Pn -p "$PORT" \
    --script "+$SCRIPT_PATH" \
    --script-args "http-vuln-php2shell.path=$path" \
    127.0.0.1
}

assert_contains() {
  local output=$1
  local expected=$2
  grep --fixed-strings --quiet "$expected" <<<"$output" || {
    printf 'Expected output to contain: %s\n' "$expected" >&2
    exit 1
  }
}

assert_not_contains() {
  local output=$1
  local unexpected=$2
  if grep --fixed-strings --quiet "$unexpected" <<<"$output"; then
    printf 'Expected output not to contain: %s\n' "$unexpected" >&2
    exit 1
  fi
}

output=$(scan /vulnerable)
assert_contains "$output" "CVE:CVE-2026-109618"
assert_contains "$output" "CVE:CVE-2026-109619"
assert_contains "$output" "raw_version=8.4.26"

output=$(scan /vendor)
assert_contains "$output" "raw_version=8.5.11-1+deb12u1"
assert_contains "$output" "below upstream fix 8.5.12"

output=$(scan /eol)
assert_contains "$output" "raw_version=7.4.33"
assert_contains "$output" "affected end-of-life branch"

output=$(scan /duplicate)
assert_contains "$output" "raw_version=8.4.27"
assert_contains "$output" "raw_version=8.3.35"
assert_contains "$output" "CVE:CVE-2026-109619"

output=$(scan /fixed)
assert_not_contains "$output" "http-vuln-php2shell:"

output=$(scan /none)
assert_not_contains "$output" "http-vuln-php2shell:"

output=$(scan /old-unassessed)
assert_not_contains "$output" "http-vuln-php2shell:"

output=$(scan //invalid)
assert_contains "$output" ".path must be an origin-relative path"

printf 'NSE integration tests passed\n'
