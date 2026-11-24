#!/usr/bin/env bash
# Prepare the lab for the live presentation, with YOUR admin password and
# YOUR phone. Afterwards the lab is at "the organisation has a root CA and a
# signed release; no user machine is enrolled yet". Then follow docs/DEMO.md.
source "$(dirname "$0")/lib.sh"

say "Starting from an empty lab (all keys and CAs are deleted)"
dc down -v --remove-orphans >/dev/null 2>&1 || true
rm -f "$LAB"/*.crt "$LAB"/*.csr "$LAB"/link-* "$LAB"/cipherdrop*
dc up -d --build root-ca control alice bob carol mallory

say "1/4  Offline root CA and release signing key"
dc exec -T root-ca root-init

say "2/4  Control server: choose the admin password, scan the QR code with Google Authenticator"
dc exec control cipherdrop-ca init --public-addr "$NET.2:47480"

say "3/4  The offline root signs the issuing CA"
./scripts/dev/carry-issuing.sh --yes
echo
echo "Log in to install it: admin password + a NEW code from your phone (codes work once)."
dc exec control cipherdrop-ca install-issuing --cert /tmp/issuing.crt --root /tmp/root.crt

say "4/4  Sign and publish the CipherDrop program"
./scripts/dev/publish-release.sh

say "Sample documents on each user machine (for sending during the demo)"
./scripts/dev/sample-docs.sh

cat <<'EOF'

Ready for the demo. Open four terminals in this folder:

  Terminal 1  root    docker compose exec control bash     then: cipherdrop-ca console
  Terminal 2  alice   docker compose exec alice bash
  Terminal 3  bob     docker compose exec bob bash
  Terminal 4  carol   docker compose exec carol bash

The script is in docs/DEMO.md.
EOF
