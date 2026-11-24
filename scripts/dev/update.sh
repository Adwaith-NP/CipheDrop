#!/usr/bin/env bash
# Roll out a new CipherDrop build to an existing lab without losing anything:
# keys, certificates, slots and the audit log all stay. The new program is
# signed offline and every enrolled machine installs it through the normal
# bootstrap: pinned download + OpenSSL signature check.
#
# For your demo lab it asks for the admin password and a 2FA code, because
# the control server must be running to serve the download.
source "$(dirname "$0")/lib.sh"
STATE=/var/lib/cipherdrop-ca

say "Rebuilding images and restarting the lab (identities are kept in volumes)"
dc up -d --build root-ca control alice bob carol mallory

./scripts/dev/publish-release.sh

say "Start the control server to serve the update"
stop_proc control "cipherdrop-ca (serve|console)"
if [ -t 0 ] && [ -z "${CIPHERDROP_ADMIN_PASSWORD:-}" ]; then
  read -rsp "Admin password: " ADMIN_PW; echo
  read -rp "2FA code from your phone: " c
else
  c="$(code)"
fi
dc exec -d -e CIPHERDROP_ADMIN_PASSWORD="$ADMIN_PW" control sh -c "cipherdrop-ca serve --code $c > /tmp/update-serve.log 2>&1"
sleep 1.5
if ! dc exec -T control ss -Hltn "sport = :47480" | grep -q .; then
  dc exec -T control cat /tmp/update-serve.log
  fail "control server did not start (wrong password or code?)"
fi

# An update link only needs the server address, its key pin and the root
# fingerprint; enrolled machines never use the slot or token in it.
b64url() { tr '+/' '-_' | tr -d '=\r\n'; }
pin="$(dc exec -T control sh -c "openssl x509 -in $STATE/tls.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A" | b64url)"
ca="$(dc exec -T control sh -c "openssl x509 -in $STATE/root.crt -outform DER | openssl dgst -sha256 -binary | openssl base64 -A" | b64url)"
link="cipherdrop://$NET.2:47480/enroll/0000000000000000?ca=$ca&pin=$pin&t=AAAAAAAAAAAAAAAAAAAAAA"

for n in alice bob carol; do
  if dc exec -T "$n" test -f /var/lib/cipherdrop/identity.crt; then
    say "$n: signed update"
    dc exec -T -u root "$n" cipherdrop-bootstrap "$link"
  else
    say "$n is not enrolled yet: it will get the new program when it enrols"
  fi
done
stop_proc control "cipherdrop-ca serve"
say "Sample documents (home folders were reset by the rebuild)"
./scripts/dev/sample-docs.sh
pass "lab updated. Reopen your terminals; on the root run: cipherdrop-ca console"
