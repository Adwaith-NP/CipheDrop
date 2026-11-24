# Shared helpers for the lab scripts. Source this file; do not run it.
set -euo pipefail
cd "$(dirname "$0")/../.."

dc() { docker compose "$@"; }

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }

# wait_port SERVICE PROTO PORT: wait until SERVICE listens (PROTO = u or t).
wait_port() {
  for _ in $(seq 1 100); do
    if dc exec -T "$1" ss -Hl"$2"n "sport = :$3" 2>/dev/null | grep -q .; then return 0; fi
    sleep 0.1
  done
  fail "$1 is not listening on port $3"
}
wait_udp() { wait_port "$1" u "$2"; }

# stop_proc SERVICE PATTERN: kill a background process left in a container.
stop_proc() { dc exec -T -u root "$1" pkill -f "$2" >/dev/null 2>&1 || true; }

# Which lab: the demo lab (default) or the test lab used by `make check`.
export CIPHERDROP_PROJECT="${CIPHERDROP_PROJECT:-cipherdrop}"
export CIPHERDROP_NET="${CIPHERDROP_NET:-192.168.56}"
NET="$CIPHERDROP_NET"

# Admin password: CIPHERDROP_ADMIN_PASSWORD if you set it (for a lab you
# initialised by hand), otherwise a random one kept out of git in .lab/.
LAB=".lab/$CIPHERDROP_PROJECT"
# Older versions kept loose files directly in .lab/, including a copy of the
# program named "cipherdrop", which would block this folder. Move it aside.
if [ -e "$LAB" ] && [ ! -d "$LAB" ]; then mv -f "$LAB" ".lab/old-$CIPHERDROP_PROJECT-file"; fi
mkdir -p "$LAB" && chmod 700 .lab "$LAB"
if [ -n "${CIPHERDROP_ADMIN_PASSWORD:-}" ]; then
  ADMIN_PW="$CIPHERDROP_ADMIN_PASSWORD"
else
  [ -s "$LAB/admin-password" ] || { openssl rand -base64 24 > "$LAB/admin-password"; chmod 600 "$LAB/admin-password"; }
  ADMIN_PW="$(cat "$LAB/admin-password")"
fi

# ca ARGS...: run cipherdrop-ca on the control server as the admin.
ca() { dc exec -T -e CIPHERDROP_ADMIN_PASSWORD="$ADMIN_PW" control cipherdrop-ca "$@"; }

# code: what the admin's Google Authenticator shows (lab only). Each code is
# single-use, so this waits for a fresh one when needed.
code() { dc exec -T -e CIPHERDROP_ADMIN_PASSWORD="$ADMIN_PW" control cipherdrop-ca dev totp | tr -d '\r'; }
