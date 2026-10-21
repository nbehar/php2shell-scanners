#!/usr/bin/env bash
set -u
set -o pipefail

PROGRAM_NAME="${0##*/}"
CONNECT_TIMEOUT=5
MAX_TIME=15
INSECURE=0
MAX_BODY_BYTES=1048576

usage() {
  cat <<USAGE
Usage: $PROGRAM_NAME [options] URL

Options:
  --connect-timeout SECONDS  Connection timeout (default: 5)
  --max-time SECONDS        Total request timeout (default: 15)
  --insecure                Disable TLS certificate verification
  -h, --help                Show this help

Exit codes:
  0  No affected PHP version was disclosed
  1  A likely affected PHP version was disclosed
  2  Usage, dependency, request, or response error
USAGE
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

is_positive_number() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] && [[ "$1" != "0" ]] && [[ "$1" != "0.0" ]]
}

while (( $# > 0 )); do
  case "$1" in
    --connect-timeout)
      (( $# >= 2 )) || fail "--connect-timeout requires a value"
      is_positive_number "$2" || fail "--connect-timeout must be positive"
      CONNECT_TIMEOUT="$2"
      shift 2
      ;;
    --max-time)
      (( $# >= 2 )) || fail "--max-time requires a value"
      is_positive_number "$2" || fail "--max-time must be positive"
      MAX_TIME="$2"
      shift 2
      ;;
    --insecure)
      INSECURE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      break
      ;;
  esac
done

(( $# == 1 )) || {
  usage >&2
  exit 2
}

TARGET_URL="$1"
case "$TARGET_URL" in
  http://*|https://*) ;;
  *) fail "URL must begin with http:// or https://" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v awk >/dev/null 2>&1 || fail "awk is required"

HEADER_FILE=$(mktemp "${TMPDIR:-/tmp}/php2shell-headers.XXXXXX") ||
  fail "could not create a temporary file"
PARSED_FILE=$(mktemp "${TMPDIR:-/tmp}/php2shell-parsed.XXXXXX") || {
  rm -f "$HEADER_FILE"
  fail "could not create a temporary file"
}
ERROR_FILE=$(mktemp "${TMPDIR:-/tmp}/php2shell-curl.XXXXXX") || {
  rm -f "$HEADER_FILE" "$PARSED_FILE"
  fail "could not create a temporary file"
}
trap 'rm -f "$HEADER_FILE" "$PARSED_FILE" "$ERROR_FILE"' EXIT HUP INT TERM

CURL_ARGS=(
  --silent
  --show-error
  --request GET
  --dump-header "$HEADER_FILE"
  --output /dev/null
  --connect-timeout "$CONNECT_TIMEOUT"
  --max-time "$MAX_TIME"
  --max-filesize "$MAX_BODY_BYTES"
  --proto '=http,https'
  --user-agent 'php2shell-exposure-bash/3.0.0'
)
if (( INSECURE )); then
  CURL_ARGS+=(--insecure)
fi

curl "${CURL_ARGS[@]}" "$TARGET_URL" 2>"$ERROR_FILE"
CURL_STATUS=$?
if (( CURL_STATUS != 0 && CURL_STATUS != 63 )); then
  cat "$ERROR_FILE" >&2
  fail "curl request failed with exit code $CURL_STATUS"
fi
[[ -s "$HEADER_FILE" ]] || fail "the server returned no HTTP headers"

awk '
function trim(value) {
  sub(/^[ \t]+/, "", value)
  sub(/[ \t]+$/, "", value)
  return value
}
/^HTTP\/[0-9.]+[ \t]+[0-9][0-9][0-9]/ {
  status = $2
  selected = ""
  saw_status = 1
  in_headers = 1
  next
}
in_headers {
  line = $0
  sub(/\r$/, "", line)
  if (line == "") {
    in_headers = 0
    next
  }
  separator = index(line, ":")
  if (separator > 1) {
    name = trim(substr(line, 1, separator - 1))
    value = trim(substr(line, separator + 1))
    lower_name = tolower(name)
    if (lower_name == "x-powered-by" || lower_name == "server") {
      selected = selected "HEADER\t" name "\t" value "\n"
    }
  }
}
END {
  if (saw_status) {
    print "STATUS\t" status
    printf "%s", selected
  }
}
' "$HEADER_FILE" >"$PARSED_FILE"

[[ -s "$PARSED_FILE" ]] || fail "could not identify an HTTP response"

CLASS_LIKELY=0
CLASS_REASON=""

classify_version() {
  local raw_version="$1"
  local major minor patch suffix qualifier fixed_patch fixed_version

  CLASS_LIKELY=0
  CLASS_REASON="unassessed malformed version token"

  if [[ ! "$raw_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
    return
  fi

  major=$((10#${BASH_REMATCH[1]}))
  minor=$((10#${BASH_REMATCH[2]}))
  patch=$((10#${BASH_REMATCH[3]}))
  suffix="${BASH_REMATCH[4]}"
  qualifier=$(printf '%s\n' "$suffix" | awk '{ print tolower($0) }')
  while [[ "$qualifier" == [-.+~]* ]]; do
    qualifier="${qualifier:1}"
  done

  if (( major < 5 || (major == 5 && minor < 4) )); then
    CLASS_REASON="outside the published affected-version range"
    return
  fi

  if (( major < 8 || (major == 8 && minor < 2) )); then
    CLASS_LIKELY=1
    CLASS_REASON="end-of-life upstream branch; verify vendor backports"
    return
  fi

  fixed_patch=""
  fixed_version=""
  if (( major == 8 )); then
    case "$minor" in
      2) fixed_patch=35; fixed_version="8.2.35" ;;
      3) fixed_patch=36; fixed_version="8.3.36" ;;
      4) fixed_patch=27; fixed_version="8.4.27" ;;
      5) fixed_patch=12; fixed_version="8.5.12" ;;
    esac
  fi

  if [[ -n "$fixed_patch" ]]; then
    if (( patch < fixed_patch )); then
      CLASS_LIKELY=1
      CLASS_REASON="below upstream fix $fixed_version"
      return
    fi
    if (( patch == fixed_patch )) && [[ "$qualifier" =~ ^(rc|alpha|beta|dev) ]]; then
      CLASS_LIKELY=1
      CLASS_REASON="prerelease preceding final upstream fix $fixed_version"
      return
    fi
    if [[ "$qualifier" =~ ^(rc|alpha|beta|dev) ]]; then
      CLASS_REASON="unassessed prerelease above upstream fix $fixed_version"
      return
    fi
    CLASS_REASON="at or above upstream fix $fixed_version"
    return
  fi

  CLASS_REASON="branch outside the published fixed-release matrix"
}

HTTP_STATUS=""
SOURCES=()
VERSIONS=()
REASONS=()
LIKELY_FLAGS=()

while IFS=$'\t' read -r record first second; do
  case "$record" in
    STATUS)
      HTTP_STATUS="$first"
      ;;
    HEADER)
      source="$first"
      value="$second"
      remaining="$value"
      while [[ "$remaining" =~ ([Pp][Hh][Pp]/([0-9]+\.[0-9]+\.[0-9]+[-[:alnum:].+~]*)) ]]; do
        matched="${BASH_REMATCH[1]}"
        raw_version="${BASH_REMATCH[2]}"
        classify_version "$raw_version"
        SOURCES+=("$source")
        VERSIONS+=("$raw_version")
        REASONS+=("$CLASS_REASON")
        LIKELY_FLAGS+=("$CLASS_LIKELY")
        remaining="${remaining#*"$matched"}"
      done
      ;;
  esac
done <"$PARSED_FILE"

printf 'PHP2Shell banner exposure check\n'
printf 'URL: %s\n' "$TARGET_URL"
printf 'HTTP status: %s\n' "${HTTP_STATUS:-unknown}"

HAS_LIKELY=0
if (( ${#VERSIONS[@]} == 0 )); then
  printf 'Evidence: no PHP version disclosed in X-Powered-By or Server\n'
else
  printf 'Evidence:\n'
  for (( index = 0; index < ${#VERSIONS[@]}; index++ )); do
    printf '  - header_source=%s raw_version=%s assessment=%s\n' \
      "${SOURCES[index]}" "${VERSIONS[index]}" "${REASONS[index]}"
    if (( LIKELY_FLAGS[index] )); then
      HAS_LIKELY=1
    fi
  done
fi

if (( HAS_LIKELY )); then
  printf 'Result: LIKELY VULNERABLE\n'
  printf 'Caveat: banner evidence alone does not confirm either CVE; verify runtime and package provenance.\n'
  exit 1
fi

printf 'Result: NO AFFECTED VERSION DISCLOSED\n'
printf 'Caveat: this result does not prove the serving runtime is patched.\n'
exit 0
