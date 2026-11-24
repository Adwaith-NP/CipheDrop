#!/usr/bin/env bash
# Evidence for the report: record the alice -> bob handshake from bob's
# network interface, writing docs/evidence/p1-handshake.pcap (open in Wireshark).
# With KEYLOG=1 the TLS secrets are saved too, so Wireshark can decrypt it.
source "$(dirname "$0")/lib.sh"

mkdir -p docs/evidence
rm -f docs/evidence/capture.pcap
say "Starting tcpdump on bob's interface"
dc --profile capture up -d sniffer
sleep 1
./scripts/dev/ping.sh
sleep 1
dc --profile capture stop sniffer >/dev/null
dc --profile capture rm -f sniffer >/dev/null
mv docs/evidence/capture.pcap docs/evidence/p1-handshake.pcap
packets="$(dc --profile capture run --rm --no-deps -T --entrypoint tcpdump sniffer -r /evidence/p1-handshake.pcap -nn 2>/dev/null | wc -l | tr -d ' ')"
pass "captured $packets UDP packets to docs/evidence/p1-handshake.pcap"
echo "In Wireshark: filter 'quic', open an Initial packet to see the ClientHello key_share group X25519MLKEM768 (0x11ec)."
