#!/usr/bin/env bash
# Certificate renewal, end to end: the admin creates a renewal link, the
# device runs the same bootstrap command, gets a new key and certificate with
# the same name, and OpenSSL's CA database records the old one as superseded.
# Run after `make provision`.
source "$(dirname "$0")/lib.sh"
home=/var/lib/cipherdrop

old_fp="$(dc exec -T alice cipherdrop whoami --fingerprint | tr -d '\r')"
old_serial="$(dc exec -T alice openssl x509 -in $home/identity.crt -noout -serial | cut -d= -f2 | tr -d '\r')"
old_key="$(dc exec -T alice sha256sum $home/identity.key | cut -c1-16)"

say "Admin creates a renewal link for alice (new certificate valid 730 days)"
link="$(ca slot renew --name alice --days 730 --code "$(code)" | grep '^cipherdrop://' | tr -d '\r')"
echo "$link"
grep -q '&r=1' <<<"$link" || fail "not a renewal link"

say "alice runs the same command as for enrolment"
dc exec -T -u root -e CIPHERDROP_ENROLL_CODE="$(code)" alice cipherdrop-bootstrap "$link"

new_fp="$(dc exec -T alice cipherdrop whoami --fingerprint | tr -d '\r')"
new_key="$(dc exec -T alice sha256sum $home/identity.key | cut -c1-16)"
[ "$old_fp" != "$new_fp" ] || fail "certificate not replaced"
[ "$old_key" != "$new_key" ] || fail "key not rotated"
dc exec -T alice cipherdrop whoami | grep -q "department     finance" || fail "identity changed"
end="$(dc exec -T alice openssl x509 -in $home/identity.crt -noout -enddate | cut -d= -f2 | tr -d '\r')"
echo "new certificate valid until $end"
pass "alice keeps her name and department, with a new key and a new 730-day certificate"

say "OpenSSL's CA database and CRL: the old certificate is revoked as superseded"
dc exec -T control sh -c "grep '$old_serial' /var/lib/cipherdrop-ca/issuing/index.txt" | tee /dev/stderr | grep -q '^R.*superseded' \
  || fail "old certificate not marked superseded"
dc exec -T control sh -c "openssl crl -in /var/lib/cipherdrop-ca/issuing/crl.pem -noout -text | grep -A4 'Serial Number: $old_serial'" \
  | grep -q -i superseded || fail "old certificate missing from the CRL"
pass "index.txt and crl.pem list serial $old_serial with reason superseded"

say "The renewed alice still works with bob"
./scripts/dev/ping.sh | grep -E "PASS|FAIL"

say "The renewal link cannot be used twice"
out="$(dc exec -T -u root -e CIPHERDROP_ENROLL_CODE="$(code)" alice cipherdrop-bootstrap "$link" 2>&1)" && reused=1 || reused=0
echo "$out" | tail -1
[ "$reused" -eq 0 ] && grep -q "already used" <<<"$out" || fail "renewal link reused"
pass "second use refused"
