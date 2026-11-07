#!/usr/bin/env bash
# Renders the credential proxy from gateway-setup.sh, points it at a local mock
# upstream that echoes what it receives, and checks that the proxy swaps in the
# token, strips client credentials, forwards only model calls, and keeps the token
# out of its logs. Runs without root.
set -uo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"

echo "credential proxy"
command -v nginx >/dev/null || { skip "nginx not installed"; exit 0; }
command -v curl >/dev/null || { skip "curl not installed"; exit 0; }

TMP="$(mktemp -d)"; chmod 755 "$TMP"
PROXY_PORT="${PROXY_PORT:-18080}" MOCK_PORT="${MOCK_PORT:-19090}"
TOKEN="test-token-not-real-0123456789"
MOCK_PID=""
cleanup() {
  [[ -f "$TMP/nginx.pid" ]] && nginx -p "$TMP" -c "$TMP/nginx.conf" -e "$TMP/error.log" -s stop 2>/dev/null
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/logs" "$TMP/tmp"

# Upstream include: the real file with the upstream URL pointed at the mock.
heredoc_body "cat > /etc/nginx/agentlab-upstream.conf <<'EOF'" "$GATEWAY_SETUP" \
  | sed "s#https://api.anthropic.com;#http://127.0.0.1:$MOCK_PORT;#" > "$TMP/agentlab-upstream.conf"
grep -q "127.0.0.1:$MOCK_PORT" "$TMP/agentlab-upstream.conf" || { bad "render upstream include"; finish; exit; }

render_heredoc 'cat > /etc/nginx/sites-available/agentlab <<EOF' \
  "GW_IP=127.0.0.1 PROXY_PORT=$PROXY_PORT LOG_DIR=$TMP/logs TOKEN_FILE=$TMP/agentlab-token.conf" \
  | sed "s#/etc/nginx/agentlab-upstream.conf#$TMP/agentlab-upstream.conf#g" > "$TMP/site.conf"
printf 'set $agentlab_token "%s";\n' "$TOKEN" > "$TMP/agentlab-token.conf"
cat > "$TMP/nginx.conf" <<EOF
worker_processes 1;
pid $TMP/nginx.pid;
error_log $TMP/error.log;
events {}
http {
  client_body_temp_path $TMP/tmp/body;
  proxy_temp_path $TMP/tmp/proxy;
  fastcgi_temp_path $TMP/tmp/fastcgi;
  uwsgi_temp_path $TMP/tmp/uwsgi;
  scgi_temp_path $TMP/tmp/scgi;
  include $TMP/site.conf;
}
EOF

cat > "$TMP/mock.py" <<'EOF'
import http.server, json, sys
class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        if not n and self.headers.get("transfer-encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline(); break
                body += self.rfile.read(size); self.rfile.readline()
        out = json.dumps({"path": self.path, "bytes": len(body),
                          "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
EOF
python3 "$TMP/mock.py" "$MOCK_PORT" & MOCK_PID=$!

check "rendered config passes nginx -t" nginx -q -t -p "$TMP" -c "$TMP/nginx.conf" -e "$TMP/error.log"
nginx -p "$TMP" -c "$TMP/nginx.conf" -e "$TMP/error.log" 2>/dev/null || { bad "nginx starts"; finish; exit; }
P="http://127.0.0.1:$PROXY_PORT"
for _ in $(seq 1 20); do curl -s -o /dev/null "$P/" && break; sleep 0.2; done

echoed="$(curl -s -X POST "$P/v1/messages?beta=true" \
  -H 'Authorization: Bearer placeholder-real-token-is-on-gateway' \
  -H 'x-api-key: should-be-stripped' -H 'X-Forwarded-For: 203.0.113.9' \
  -H 'anthropic-beta: oauth-2025-04-20' -d '{"model":"x"}')"
field() {   # field KEY [SUBKEY]: print a value from the echoed request, or None
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])
for k in sys.argv[2:]:
    d = d.get(k) if isinstance(d, dict) else None
print(d)' "$echoed" "$@" 2>/dev/null
}
check  "model call is forwarded with the real token" test "$(field headers authorization)" = "Bearer $TOKEN"
check  "client x-api-key is stripped" test "$(field headers x-api-key)" = None
check  "client X-Forwarded-For is stripped" test "$(field headers x-forwarded-for)" = None
check  "Host is api.anthropic.com" test "$(field headers host)" = api.anthropic.com
check  "query string passes through" test "$(field path)" = "/v1/messages?beta=true"
check  "other headers pass through (anthropic-beta)" test "$(field headers anthropic-beta)" = oauth-2025-04-20

code() { curl -s -o /dev/null -w '%{http_code}' --path-as-is "$@"; }
check "POST /v1/messages/count_tokens is allowed" test "$(code -X POST "$P/v1/messages/count_tokens" -d '{}')" = 200
check "GET /v1/messages is refused" test "$(code "$P/v1/messages")" = 403
for path in / /v1/models /v1/files /v1/messages/batches /v1/complete /api/oauth/profile \
            /v1/messages/../models /v1/messages/count_tokens/x /V1/MESSAGES /v1/messages%2F..%2Fmodels; do
  check "POST $path is refused" test "$(code -X POST "$P$path" -d '{}')" = 403
done

head -c 5000000 /dev/zero | tr '\0' a > "$TMP/big"
big="$(curl -s -X POST "$P/v1/messages" --data-binary @"$TMP/big" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["bytes"])' 2>/dev/null)"
check "5 MB request body is forwarded whole" test "$big" = 5000000

sleep 0.3
refuse "token never appears in proxy logs" grep -rqF "$TOKEN" "$TMP/logs" "$TMP/error.log"
check  "log lines have time, client, method, path, status, size, duration" \
  awk 'NF != 7 { exit 1 }' "$TMP/logs/credproxy.log"
finish
