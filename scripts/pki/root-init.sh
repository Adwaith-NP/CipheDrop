#!/usr/bin/env bash
# Create the offline root of trust. Run once, on a machine with no network.
#
#   root-init.sh
#
# Creates two independent Ed25519 keys:
#   private/ca.key       root CA key: signs the issuing CA certificate
#   private/release.key  release key: signs the CipherDrop program itself
# Keeping them apart means a stolen release key cannot mint certificates,
# and a stolen CA key cannot push software.
set -euo pipefail

PKI_DIR="${CIPHERDROP_PKI_DIR:-$(dirname "$(readlink -f "$0")")}"
CNF="$PKI_DIR/ca.cnf"
export CA_HOME="${CA_HOME:-/ca-root}"
export CD_DEVICE_NAME=unused

if [ -f "$CA_HOME/ca.crt" ]; then
  echo "Root CA already exists in $CA_HOME, keeping it."
else
  umask 077
  mkdir -p "$CA_HOME/private" "$CA_HOME/newcerts" "$CA_HOME/certs"
  : > "$CA_HOME/index.txt"
  openssl rand -hex 16 > "$CA_HOME/serial"
  echo 1000 > "$CA_HOME/crlnumber"

  openssl genpkey -algorithm ed25519 -out "$CA_HOME/private/ca.key"
  openssl req -x509 -new -config "$CNF" -key "$CA_HOME/private/ca.key" \
    -subj "/O=CipherDrop/CN=CipherDrop Root CA" -extensions ext_root -days 3650 \
    -out "$CA_HOME/ca.crt"
  openssl genpkey -algorithm ed25519 -out "$CA_HOME/private/release.key"
  openssl pkey -in "$CA_HOME/private/release.key" -pubout -out "$CA_HOME/release.pub"
  chmod 644 "$CA_HOME/ca.crt" "$CA_HOME/release.pub"
  echo "Created the CipherDrop root CA and release signing key in $CA_HOME"
fi

openssl x509 -in "$CA_HOME/ca.crt" -noout -subject -enddate
printf 'root CA fingerprint  %s\n' "$(openssl x509 -in "$CA_HOME/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
printf 'release key SHA-256  %s\n' "$(openssl pkey -pubin -in "$CA_HOME/release.pub" -outform DER | openssl dgst -sha256 | awk '{print $2}')"
