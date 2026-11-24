#!/usr/bin/env bash
# Sign a CipherDrop release with the offline release key (Ed25519).
#
#   release-sign.sh FILE        writes FILE.sig
#
# New machines verify this signature with OpenSSL before installing, so even
# a compromised control server cannot hand out a modified program.
set -euo pipefail
export CA_HOME="${CA_HOME:-/ca-root}"
[ $# -eq 1 ] || { sed -n '2,6p' "$0"; exit 2; }
file="$1"

openssl pkeyutl -sign -rawin -inkey "$CA_HOME/private/release.key" -in "$file" -out "$file.sig"
openssl pkeyutl -verify -rawin -pubin -inkey "$CA_HOME/release.pub" -in "$file" -sigfile "$file.sig" >/dev/null
chmod 644 "$file.sig"
printf 'signed  %s\nSHA-256 %s\n' "$file" "$(openssl dgst -sha256 "$file" | awk '{print $2}')"
