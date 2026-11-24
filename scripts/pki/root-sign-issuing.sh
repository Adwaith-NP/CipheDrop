#!/usr/bin/env bash
# Sign the control server's issuing CA request with the offline root.
#
#   root-sign-issuing.sh [--yes] issuing.csr [issuing.crt]
#
# Checks: the CSR's own signature (proof the control server holds the key),
# an Ed25519 key, and a name starting with "CipherDrop Issuing CA".
set -euo pipefail

PKI_DIR="${CIPHERDROP_PKI_DIR:-$(dirname "$(readlink -f "$0")")}"
CNF="$PKI_DIR/ca.cnf"
export CA_HOME="${CA_HOME:-/ca-root}"
export CD_DEVICE_NAME=unused

assume_yes=0
if [ "${1:-}" = "--yes" ]; then assume_yes=1; shift; fi
[ $# -ge 1 ] || { sed -n '2,7p' "$0"; exit 2; }
csr="$1"
out="${2:-${csr%.csr}.crt}"

openssl req -in "$csr" -noout -verify 2>/dev/null || { echo "REFUSED: CSR signature does not verify" >&2; exit 1; }
openssl req -in "$csr" -noout -text | grep -q "Public Key Algorithm: ED25519" || { echo "REFUSED: not an Ed25519 key" >&2; exit 1; }
subject="$(openssl req -in "$csr" -noout -subject -nameopt RFC2253)"
case "$subject" in
  *"CN=CipherDrop Issuing CA"*) ;;
  *) echo "REFUSED: unexpected subject: $subject" >&2; exit 1 ;;
esac

echo "Issuing CA request: $subject"
printf 'public key SHA-256: %s\n' "$(openssl req -in "$csr" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $2}')"
if [ "$assume_yes" -ne 1 ]; then
  read -r -p "Sign this issuing CA for 5 years? [y/N] " a
  case "$a" in y|Y|yes) ;; *) echo "Not signed."; exit 1 ;; esac
fi

openssl ca -batch -notext -config "$CNF" -extensions ext_issuing -days 1825 \
  -in "$csr" -out "$out" 2>/dev/null || { echo "REFUSED by openssl ca (already issued?)" >&2; exit 1; }
chmod 644 "$out"
openssl verify -CAfile "$CA_HOME/ca.crt" "$out"
openssl x509 -in "$out" -noout -subject -enddate -fingerprint -sha256
