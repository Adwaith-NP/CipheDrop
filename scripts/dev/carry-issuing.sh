#!/usr/bin/env bash
# Carry the issuing CA request from the control server to the offline root,
# let the root sign it, and carry the certificates back. In the lab,
# `docker compose cp` plays the USB stick between the two machines.
#
#   carry-issuing.sh          the root asks "Sign this issuing CA? [y/N]"
#   carry-issuing.sh --yes    no question (used by make provision)
source "$(dirname "$0")/lib.sh"
STATE=/var/lib/cipherdrop-ca

sign_args=(root-sign-issuing)
exec_flags=()
if [ "${1:-}" = "--yes" ]; then sign_args+=(--yes); exec_flags=(-T); fi

say "USB stick: control server -> offline root (issuing.csr)"
dc cp control:"$STATE/issuing.csr" "$LAB/issuing.csr" 2>/dev/null
dc cp "$LAB/issuing.csr" root-ca:/tmp/issuing.csr 2>/dev/null

say "Offline root CA checks and signs the issuing CA"
dc exec ${exec_flags[@]+"${exec_flags[@]}"} root-ca "${sign_args[@]}" /tmp/issuing.csr /tmp/issuing.crt

say "USB stick: offline root -> control server (issuing.crt, root ca.crt)"
dc cp root-ca:/tmp/issuing.crt "$LAB/issuing.crt" 2>/dev/null
dc cp root-ca:/ca-root/ca.crt "$LAB/root.crt" 2>/dev/null
dc cp "$LAB/issuing.crt" control:/tmp/issuing.crt 2>/dev/null
dc cp "$LAB/root.crt" control:/tmp/root.crt 2>/dev/null
pass "certificates delivered to the control server: /tmp/issuing.crt and /tmp/root.crt"
