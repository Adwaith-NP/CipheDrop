#!/usr/bin/env bash
# Zero-trust provisioning of the lab, end to end:
#   offline root -> issuing CA on the control server -> signed release ->
#   one-time slots -> blank machines bootstrap themselves with the admin's 2FA.
# Every admin step needs the password plus a fresh 2FA code, and codes are
# single-use, so the script pauses up to 30 s between steps.
source "$(dirname "$0")/lib.sh"
STATE=/var/lib/cipherdrop-ca

say "1. Offline root CA and release signing key (root-ca has no network)"
dc exec -T root-ca root-init

say "2. Control server: vault, 2FA secret, encrypted issuing CA key"
if dc exec -T control test -f "$STATE/vault.json"; then
  echo "already initialised"
else
  ca init --name control --public-addr "$NET.2:47480" --skip-confirm
fi

if dc exec -T control test -f "$STATE/tls.crt"; then
  say "3. Issuing CA already installed"
else
  say "3. Carry the issuing CA request to the offline root and back"
  ./scripts/dev/carry-issuing.sh --yes
  ca install-issuing --cert /tmp/issuing.crt --root /tmp/root.crt --code "$(code)"
fi

say "4. Sign the release offline and publish it on the control server"
./scripts/dev/publish-release.sh

say "5. Start the control server (admin login: password + 2FA)"
stop_proc control "cipherdrop-ca serve"
c="$(code)"
dc exec -d -e CIPHERDROP_ADMIN_PASSWORD="$ADMIN_PW" control sh -c "cipherdrop-ca serve --code $c > /tmp/control.log 2>&1"
wait_port control t 47480
dc exec -T control cat /tmp/control.log

for spec in "alice:finance:payroll exports" "bob:legal:contract archive" "carol:hr:staff records"; do
  IFS=: read -r name dept purpose <<<"$spec"
  if dc exec -T "$name" test -f /var/lib/cipherdrop/identity.crt; then
    if dc exec -T "$name" test -x /usr/local/bin/cipherdrop; then
      say "$name is already enrolled"
    else
      say "$name is enrolled but its container was rebuilt: reinstall the signed program"
      dc exec -T -u root "$name" cipherdrop-bootstrap "$(cat "$LAB/link-$name.txt")"
    fi
    continue
  fi
  say "6. Admin creates a one-time slot for $name ($dept)"
  link="$(ca slot add --name "$name" --dept "$dept" --purpose "$purpose" --code "$(code)" | grep '^cipherdrop://' | tr -d '\r')"
  echo "$link"
  echo "$link" > "$LAB/link-$name.txt"
  say "7. $name (blank machine) runs the bootstrap; the admin reads out a 2FA code"
  dc exec -T -u root -e CIPHERDROP_ENROLL_CODE="$(code)" "$name" cipherdrop-bootstrap "$link"
done

say "8. Verify the result"
for n in alice bob carol; do
  dc exec -T "$n" cipherdrop whoami
  dc exec -T "$n" openssl verify -CAfile /var/lib/cipherdrop/ca.crt -untrusted /var/lib/cipherdrop/chain.crt \
    /var/lib/cipherdrop/identity.crt || fail "$n certificate does not verify with OpenSSL"
done
ca audit verify --last 12
pass "lab provisioned: alice, bob and carol enrolled through the zero-trust flow"
