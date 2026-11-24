#!/usr/bin/env bash
# CipherDrop bootstrap: turn a blank Linux machine into an enrolled CipherDrop
# device, using a one-time link from the admin.
#
#   sudo cipherdrop-bootstrap 'cipherdrop://HOST:PORT/enroll/SLOT?t=...&pin=...&ca=...'
#
# This script ships in the organisation's machine image together with the
# release public key (release.pub). It:
#   1. downloads the CipherDrop program over HTTPS (TLS 1.3), accepting only
#      the control server whose public key matches the pin in the link
#   2. verifies the program's Ed25519 release signature with OpenSSL
#   3. installs it and runs `cipherdrop enroll` as the service user, which
#      generates the device key locally and asks for the admin's 2FA code
set -euo pipefail

RELEASE_PUB="${CIPHERDROP_RELEASE_PUB:-/usr/local/share/cipherdrop/release.pub}"
SERVICE_USER="${CIPHERDROP_USER:-cipherdrop}"
HOME_DIR="${CIPHERDROP_HOME:-/var/lib/cipherdrop}"

die() { echo "bootstrap: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: cipherdrop-bootstrap 'cipherdrop://...'"
[ "$(id -u)" -eq 0 ] || die "run as root (it installs /usr/local/bin/cipherdrop)"
[ -r "$RELEASE_PUB" ] || die "release public key $RELEASE_PUB is missing from this machine image"
link="$1"

re='^cipherdrop://([A-Za-z0-9.:-]+)/enroll/([0-9a-f]{16})\?(.*)$'
[[ "$link" =~ $re ]] || die "this is not a CipherDrop enrolment link"
host="${BASH_REMATCH[1]}"
query="${BASH_REMATCH[3]}"
pin=""
IFS='&' read -ra params <<<"$query"
for kv in "${params[@]}"; do
  case "$kv" in pin=*) pin="${kv#pin=}" ;; esac
done
[[ "$pin" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "the link has no valid server pin"
pin_std="$(printf '%s=' "$pin" | tr '_-' '/+')" # base64url -> base64 for curl

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fetch() {
  # --insecure switches off CA-chain checking only. The public-key pin is
  # still enforced, and it is stricter: exactly one server key is accepted.
  curl --fail --silent --show-error --proto '=https' --tlsv1.3 --insecure \
    --pinnedpubkey "sha256//$pin_std" --max-time 120 \
    -o "$tmp/$1" "https://$host/v1/release/$1"
}

echo "[1/3] Downloading CipherDrop from the control server at $host (key-pinned TLS 1.3)"
fetch cipherdrop || die "download refused: the server at $host did not prove the pinned key"
fetch cipherdrop.sig || die "could not download the release signature"

echo "[2/3] Verifying the Ed25519 release signature with OpenSSL"
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$RELEASE_PUB" \
  -in "$tmp/cipherdrop" -sigfile "$tmp/cipherdrop.sig" >/dev/null 2>&1; then
  die "SIGNATURE INVALID: the program is not the signed release; refusing to install"
fi
echo "      signature valid, SHA-256 $(openssl dgst -sha256 "$tmp/cipherdrop" | awk '{print $2}')"

echo "[3/3] Installing /usr/local/bin/cipherdrop and enrolling as user $SERVICE_USER"
install -m 0755 -o root -g root "$tmp/cipherdrop" /usr/local/bin/cipherdrop
id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$HOME_DIR"
code_args=()
if [ -n "${CIPHERDROP_ENROLL_CODE:-}" ]; then code_args=(--code "$CIPHERDROP_ENROLL_CODE"); fi
renew=0
case "&$query&" in *"&r=1&"*) renew=1 ;; esac
if [ -f "$HOME_DIR/identity.crt" ]; then
  if [ "$renew" -eq 1 ]; then
    # Renewal link: same name and department, new key and certificate.
    echo "      renewal link: renewing this machine's key and certificate"
    exec runuser -u "$SERVICE_USER" -- env CIPHERDROP_HOME="$HOME_DIR" \
      /usr/local/bin/cipherdrop renew "$link" ${code_args[@]+"${code_args[@]}"}
  fi
  # Already enrolled and a normal link: this run was a signed software
  # update. The identity (key and certificate) is untouched.
  echo "      this machine is already enrolled; CipherDrop updated to the verified release"
  exec runuser -u "$SERVICE_USER" -- env CIPHERDROP_HOME="$HOME_DIR" /usr/local/bin/cipherdrop whoami
fi
[ "$renew" -eq 0 ] || die "this is a renewal link, but this machine is not enrolled; ask the admin for an enrolment link"
exec runuser -u "$SERVICE_USER" -- env CIPHERDROP_HOME="$HOME_DIR" \
  /usr/local/bin/cipherdrop enroll "$link" ${code_args[@]+"${code_args[@]}"}
