#!/usr/bin/env bash
# Attack demos. Every attack must FAIL. Run after `make provision`.
#   1-2  impersonation on the data channel (QUIC + mutual TLS)
#   3-6  attacks on provisioning: fake control server, tampered release,
#        stolen enrolment link, edited audit log
# Needs the control server running (make provision, or `cipherdrop-ca serve`).
# If you initialised the control server by hand, export your admin password:
#   CIPHERDROP_ADMIN_PASSWORD='...' make attacks
source "$(dirname "$0")/lib.sh"
STATE=/var/lib/cipherdrop-ca

say "Attack 1: Mallory runs a fake 'bob' receiver; alice is tricked into dialing it"
stop_proc mallory "rogue"
dc exec -d mallory sh -c 'rogue -mode receiver -name bob -addr :47475 -wait 8s > /tmp/rogue.log 2>&1'
wait_udp mallory 47475
if out="$(dc exec -T alice cipherdrop dev ping --to bob --addr "$NET.66:47475" 2>&1)"; then
  echo "$out"; fail "alice accepted Mallory's fake bob"
fi
echo "alice: $out"
grep -q "certificate signed by unknown authority" <<<"$out" || fail "rejected, but not for the expected reason"
stop_proc mallory "rogue"
pass "alice refused the self-signed 'bob' (unknown authority)"

say "Attack 2: Mallory connects to bob claiming to be 'alice'"
stop_proc bob "cipherdrop (dev listen|receive|console)"
dc exec -d bob sh -c 'cipherdrop dev listen > /tmp/listen-attack.log 2>&1'
wait_udp bob 47475
dc exec -T mallory rogue -mode client -name alice -addr "$NET.20:47475" || fail "bob accepted Mallory's fake alice"
stop_proc bob "cipherdrop (dev listen|receive|console)"
pass "bob refused a sender without a CA-signed certificate"

laptop="new-laptop-$(date +%H%M%S)"
say "Setup: the admin creates a slot for '$laptop'; Mallory steals the link before it is used"
link="$(ca slot add --name "$laptop" --dept it --purpose "attack demo" --ttl 10m --code "$(code)" | grep '^cipherdrop://' | tr -d '\r')"
echo "$link"

say "Attack 3: Mallory impersonates the control server (e.g. by ARP spoofing its IP)"
stop_proc mallory "s_server"
dc exec -T mallory sh -c 'openssl req -x509 -newkey ed25519 -nodes -keyout /tmp/fake.key -out /tmp/fake.crt -subj /CN=control -days 1 2>/dev/null'
dc exec -d mallory sh -c 'openssl s_server -accept 47480 -cert /tmp/fake.crt -key /tmp/fake.key -www -quiet > /tmp/fake.log 2>&1'
wait_port mallory t 47480
fake_link="${link/$NET.2:/$NET.66:}"
if out="$(dc exec -T -u root alice cipherdrop-bootstrap "$fake_link" 2>&1)"; then
  echo "$out"; fail "bootstrap trusted Mallory's server"
fi
echo "$out"
grep -q "did not prove the pinned key" <<<"$out" || fail "refused, but not by the key pin"
stop_proc mallory "s_server"
pass "bootstrap refused a server without the pinned key (nothing downloaded)"

say "Attack 4: a tampered program on the control server (compromised server or storage)"
dc exec -T -u root control sh -c "cp $STATE/release/cipherdrop /tmp/release.bak && printf 'backdoor' >> $STATE/release/cipherdrop"
out="$(dc exec -T -u root alice cipherdrop-bootstrap "$link" 2>&1)" && ok=1 || ok=0
dc exec -T -u root control sh -c "cp /tmp/release.bak $STATE/release/cipherdrop"
echo "$out"
[ "$ok" -eq 0 ] || fail "a tampered program was installed"
grep -q "SIGNATURE INVALID" <<<"$out" || fail "refused, but not by the signature check"
pass "OpenSSL rejected the modified program before installation"

say "Attack 5: Mallory uses the stolen link but does not have the admin's 2FA code"
stolen="$link"
for guess in 000000 111111 222222 333333 444444; do
  out="$(dc exec -T mallory cipherdrop --home /tmp/m-$guess enroll "$stolen" --code "$guess" 2>&1)" && fail "guess $guess was accepted"
  echo "guess $guess: ${out##*: }"
done
real="$(code)"
out="$(dc exec -T mallory cipherdrop --home /tmp/m-real enroll "$stolen" --code "$real" 2>&1)" && fail "locked slot accepted the real code"
echo "even the real code now: ${out##*: }"
grep -q "locked" <<<"$out" || fail "slot was not locked"
pass "5 wrong guesses locked the slot (attacker odds: 5 in 1,000,000)"

say "Attack 6: someone edits the audit log to hide alice's enrolment"
dc exec -T control sh -c "cp $STATE/audit.log /tmp/audit.bak && sed -i '0,/\"finance\"/s//\"admins\"/' $STATE/audit.log"
out="$(ca audit verify 2>&1)" && ok=1 || ok=0
dc exec -T control sh -c "cp /tmp/audit.bak $STATE/audit.log"
echo "$out"
[ "$ok" -eq 0 ] || fail "edited audit log verified"
pass "the edit broke the hash chain and was detected"
ca audit verify --last 3 >/dev/null && pass "restored audit log verifies again"
