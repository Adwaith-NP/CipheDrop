#!/usr/bin/env bash
# P1 acceptance, happy path: alice reaches bob over QUIC + mutual TLS 1.3.
# Set KEYLOG=1 to also write TLS secrets for Wireshark (debug only).
source "$(dirname "$0")/lib.sh"

keylog_flag=()
if [ "${KEYLOG:-0}" = "1" ]; then keylog_flag=(--keylog /tmp/alice-keylog.txt); fi

stop_proc bob "cipherdrop (dev listen|receive|console)"
say "bob: listening"
dc exec -d bob sh -c 'cipherdrop dev listen --once > /tmp/listen.log 2>&1'
wait_udp bob 47475

bob_fp="$(dc exec -T bob cipherdrop whoami --fingerprint | tr -d '\r')"
say "alice: ping bob (pinned to fingerprint ${bob_fp:0:23}...)"
out="$(dc exec -T alice cipherdrop dev ping --to bob --pin "$bob_fp" ${keylog_flag[@]+"${keylog_flag[@]}"})" || { echo "$out"; fail "alice could not reach bob"; }
echo "$out"
sleep 0.5
say "bob's side"
dc exec -T bob cat /tmp/listen.log

grep -q "key exchange   X25519MLKEM768" <<<"$out" || fail "hybrid post-quantum key exchange not negotiated"
grep -q "TLS            TLS 1.3" <<<"$out" || fail "not TLS 1.3"
grep -q "reply: PONG bob" <<<"$out" || fail "no PONG from bob"
code_a="$(awk '/verify code/ {print $3, $4}' <<<"$out")"
code_b="$(dc exec -T bob awk '/verify code/ {print $3, $4}' /tmp/listen.log | tr -d '\r')"
[ "$code_a" = "$code_b" ] || fail "verification codes differ: alice=$code_a bob=$code_b"
pass "mutual TLS 1.3 over QUIC, X25519MLKEM768, codes match ($code_a)"

if [ "${KEYLOG:-0}" = "1" ]; then
  dc exec -T alice cat /tmp/alice-keylog.txt > docs/evidence/alice-keylog.txt
  echo "Key log saved to docs/evidence/alice-keylog.txt (git-ignored)."
fi
