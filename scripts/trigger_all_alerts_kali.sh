#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TDR_URL="${TDR_URL:-http://localhost:8000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-pass12345678}"
LAB_ANALYST_USER="${LAB_ANALYST_USER:-analystlab}"

COOKIE_FILE="$(mktemp)"
trap 'rm -f "$COOKIE_FILE"' EXIT

json_get() {
  python3 - "$1" <<'PY'
import json,sys
key = sys.argv[1]
data = json.load(sys.stdin)
val = data
for part in key.split("."):
    val = val[part]
print(val)
PY
}

csrf_token() {
  local out token
  for _ in 1 2 3 4; do
    out="$(curl -s -c "$COOKIE_FILE" "$BASE_URL/api/csrf-token" || true)"
    token="$(printf '%s' "$out" | json_get csrfToken 2>/dev/null || true)"
    if [[ -n "$token" ]]; then
      printf '%s\n' "$token"
      return 0
    fi
    sleep 10
  done
  return 1
}

login_user() {
  local user="$1"
  local pass="$2"
  local csrf out token
  for _ in 1 2 3 4; do
    csrf="$(csrf_token)"
    out="$(curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
      -H "x-csrf-token: $csrf" \
      -H "content-type: application/json" \
      -d "{\"username\":\"$user\",\"password\":\"$pass\"}" \
      "$BASE_URL/api/auth/login" || true)"
    token="$(printf '%s' "$out" | json_get accessToken 2>/dev/null || true)"
    if [[ -n "$token" ]]; then
      printf '%s\n' "$out"
      return 0
    fi
    sleep 70
  done
  return 1
}

safe_curl() {
  set +e
  "$@" >/dev/null 2>&1
  set -e
}

ADMIN_LOGIN_JSON="$(login_user "$ADMIN_USER" "$ADMIN_PASS")"
ADMIN_TOKEN="$(printf '%s' "$ADMIN_LOGIN_JSON" | json_get accessToken)"
ADMIN_CSRF="$(csrf_token)"

curl -s -X POST "$TDR_URL/test-ips" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"ip":"172.18.0.1","source":"lab-script-kali"}' >/dev/null

curl -s -X DELETE "$TDR_URL/alerts" -H "authorization: Bearer $ADMIN_TOKEN" >/dev/null
sleep 1

# Ensure lab analyst account exists and has known temporary password
CREATE_JSON="$(
  curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/api/auth/register" \
    -H "authorization: Bearer $ADMIN_TOKEN" \
    -H "x-csrf-token: $ADMIN_CSRF" \
    -H "content-type: application/json" \
    -d "{\"username\":\"$LAB_ANALYST_USER\",\"role\":\"analyst\"}"
)"

if printf '%s' "$CREATE_JSON" | grep -q '"temporaryPassword"'; then
  ANALYST_PASS="$(printf '%s' "$CREATE_JSON" | json_get temporaryPassword)"
else
  USERS_JSON="$(curl -s -b "$COOKIE_FILE" "$BASE_URL/api/auth/users" -H "authorization: Bearer $ADMIN_TOKEN")"
  TARGET_ID="$(python3 - <<PY
import json
users=json.loads('''$USERS_JSON''')
name='$LAB_ANALYST_USER'
for u in users:
    if u.get('username')==name:
        print(u.get('id',''))
        break
PY
)"
  RESET_JSON="$(
    curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/api/auth/users/$TARGET_ID/reset-password" \
      -H "authorization: Bearer $ADMIN_TOKEN" \
      -H "x-csrf-token: $ADMIN_CSRF" \
      -H "content-type: application/json" \
      -d '{}'
  )"
  ANALYST_PASS="$(printf '%s' "$RESET_JSON" | json_get temporaryPassword)"
fi

# PRIV_ESC_ATTEMPT
ANALYST_LOGIN_JSON="$(login_user "$LAB_ANALYST_USER" "$ANALYST_PASS")"
ANALYST_TOKEN="$(printf '%s' "$ANALYST_LOGIN_JSON" | json_get accessToken)"
safe_curl curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/auth/users" -H "authorization: Bearer $ANALYST_TOKEN"

# ACCOUNT_ENUMERATION
for u in enum001 enum002 enum003 enum004 enum005; do
  safe_curl curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/api/auth/login" \
    -H "x-csrf-token: $ADMIN_CSRF" -H "content-type: application/json" \
    -d "{\"username\":\"$u\",\"password\":\"wrongpass12345\"}"
done

# Allow temporary IP login lock to expire, then re-login admin to clear counters.
sleep 35
ADMIN_LOGIN_JSON="$(login_user "$ADMIN_USER" "$ADMIN_PASS")"
ADMIN_TOKEN="$(printf '%s' "$ADMIN_LOGIN_JSON" | json_get accessToken)"
ADMIN_CSRF="$(csrf_token)"

# FAILED_LOGIN_BURST
for _ in 1 2 3 4 5; do
  safe_curl curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/api/auth/login" \
    -H "x-csrf-token: $ADMIN_CSRF" -H "content-type: application/json" \
    -d "{\"username\":\"$LAB_ANALYST_USER\",\"password\":\"wrongpass12345\"}"
done

# HONEYPOT + PATH_TRAVERSAL
safe_curl curl -s "$BASE_URL/internal-debug"
safe_curl curl -s "$BASE_URL/admin-backup?path=../etc/passwd"

# EXCESSIVE_API_CALLS + ABNORMAL_REQUEST_FREQUENCY
for _ in $(seq 1 170); do
  safe_curl curl -s "$BASE_URL/api/health"
done

sleep 4
ALERTS_JSON="$(curl -s "$TDR_URL/alerts/categorized" -H "authorization: Bearer $ADMIN_TOKEN")"
python3 - <<PY
import json
data=json.loads('''$ALERTS_JSON''')
types=sorted({a.get('type','UNKNOWN') for a in data.get('applicationAlerts',[])})
print("ALERT_TYPES=" + ",".join(types))
print("ALERT_COUNT=" + str(len(data.get('applicationAlerts',[]))))
PY
