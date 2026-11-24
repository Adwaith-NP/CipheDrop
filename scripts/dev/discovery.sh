#!/usr/bin/env bash
# P4 acceptance: consoles find each other by signed beacons and verify each
# other with a mutual TLS handshake; Mallory's fake and replayed beacons are
# listed in red, on the user consoles and on the root console.
# Run after `make provision`.
source "$(dirname "$0")/lib.sh"

for n in alice bob carol; do stop_proc "$n" "cipherdrop (dev listen|receive|console)"; done
stop_proc mallory "rogue"

say "bob, carol and alice open their consoles"
for n in bob carol; do
  dc exec -d "$n" sh -c '(sleep 120; echo quit) | cipherdrop console > /tmp/console.log 2>&1'
done
sleep 1
dc exec -d alice sh -c '(sleep 9; echo peers; sleep 1; echo quit) | cipherdrop console > /tmp/console.log 2>&1'
sleep 2

say "Mallory broadcasts fake 'bob' beacons and replays a captured beacon of carol's"
dc exec -d mallory sh -c 'rogue -mode beacon -name bob -for 120s > /tmp/fake-beacon.log 2>&1'
dc exec -T mallory rogue -mode replay -name carol -wait 10s
sleep 8

say "alice's console"
out="$(dc exec -T alice cat /tmp/console.log)"
echo "$out"
grep -Eq "● bob +legal .*verified" <<<"$out" || fail "bob not verified on alice"
grep -Eq "● carol +hr .*verified" <<<"$out" || fail "carol not verified on alice"
pass "bob and carol found by beacon and verified both ways (mutual TLS)"
grep -q 'UNVERIFIED device claiming "bob"' <<<"$out" || fail "fake bob not flagged"
grep -Eq '✗ "bob" .*NOT VERIFIED: certificate not trusted' <<<"$out" || fail "fake bob not listed in red"
pass "Mallory's self-signed 'bob' beacon is listed as NOT VERIFIED"
grep -q 'replayed beacon' <<<"$out" || fail "replayed beacon not detected"
pass "Mallory's replay of carol's genuine beacon is rejected (nonce already seen)"

say "The root console sees the same network (admin login: password + 2FA)"
c="$(code)"
root_out="$( (sleep 5; echo devices; echo quit) | dc exec -T -e CIPHERDROP_ADMIN_PASSWORD="$ADMIN_PW" control \
  cipherdrop-ca console --addr :47481 --code "$c")"
echo "$root_out"
grep -Eq "^  bob +legal +enrolled +● online" <<<"$root_out" || fail "bob not shown as enrolled and online"
grep -q "Unverified devices on the network" <<<"$root_out" || fail "root did not list the fake device"
pass "root lists registered devices with online state, and the unverified one in red"

for n in bob carol; do stop_proc "$n" "cipherdrop console"; done
stop_proc mallory "rogue"
