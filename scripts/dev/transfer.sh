#!/usr/bin/env bash
# P3 acceptance: alice sends a folder (with a 50 MB file) to bob, chats while
# it moves, and both sides end up with verifiable non-repudiation evidence.
# Run after `make provision`.
source "$(dirname "$0")/lib.sh"

say "bob waits for files (accepts from alice without asking)"
stop_proc bob "cipherdrop (dev listen|receive|console)"
dc exec -d bob sh -c 'cipherdrop receive --accept-from alice > /tmp/receive.log 2>&1'
wait_udp bob 47475

say "alice prepares an outbox: a report, a 50 MB dataset and a source folder"
dc exec -T alice sh -c 'rm -rf ~/outbox && mkdir -p ~/outbox/project/src \
  && echo "Q3 payroll summary" > ~/outbox/report.txt \
  && head -c 52428800 /dev/urandom > ~/outbox/project/dataset.bin \
  && printf "package main\n" > ~/outbox/project/src/main.go'
sums_alice="$(dc exec -T alice sh -c 'cd ~/outbox && sha256sum report.txt project/dataset.bin project/src/main.go' | tr -d '\r')"

say "alice sends it to bob, and chats with him while the 50 MB file moves"
dc exec -T alice sh -c 'cipherdrop send --to bob --note "Q3 payroll" ~/outbox/report.txt ~/outbox/project > /tmp/send.log 2>&1 &
  sleep 0.3; cipherdrop msg --to bob "sending the Q3 files now"; wait $!; cat /tmp/send.log' | tee "$LAB/send.out"
grep -q "signed receipt verified" "$LAB/send.out" || fail "no verified receipt"

say "bob's terminal"
sleep 0.5
dc exec -T bob cat /tmp/receive.log

rcpt="$(sed -n 's/.*proof of delivery saved: //p' "$LAB/send.out" | tr -d '\r')"
id="$(basename "$rcpt" .receipt.json)"

say "Integrity: SHA-256 on bob must equal SHA-256 on alice"
sums_bob="$(dc exec -T bob sh -c "cd /var/lib/cipherdrop/inbox/alice-${id:0:8} && sha256sum report.txt project/dataset.bin project/src/main.go" | tr -d '\r')"
echo "$sums_bob"
[ "$sums_alice" = "$sums_bob" ] || fail "file contents differ"
pass "all three files arrived bit-for-bit"

say "Non-repudiation: check bob's signed receipt with CipherDrop..."
dc exec -T alice cipherdrop verify "$rcpt" --export /tmp/receipt-export

say "...and independently with plain OpenSSL 3.5 (no CipherDrop code involved)"
dc exec -T alice sh -c 'cd /tmp/receipt-export \
  && openssl verify -CAfile /var/lib/cipherdrop/ca.crt -untrusted chain.pem signer.pem \
  && openssl x509 -in signer.pem -noout -subject \
  && openssl x509 -in signer.pem -pubkey -noout > signer.pub \
  && openssl pkeyutl -verify -rawin -pubin -inkey signer.pub -in signed.bin -sigfile signature.bin' \
  || fail "OpenSSL could not verify the receipt"
pass "bob's receipt is a valid Ed25519 signature by bob's CA-issued key (OpenSSL agrees)"

say "Tampering with the saved receipt is detected"
dc exec -T alice sh -c "cp '$rcpt' /tmp/forged.json && sed -i 's/\"payload\": \"/\"payload\": \"A/' /tmp/forged.json"
if dc exec -T alice cipherdrop verify /tmp/forged.json >/dev/null 2>&1; then fail "forged receipt verified"; fi
pass "an edited receipt no longer verifies"
stop_proc bob "cipherdrop receive"
