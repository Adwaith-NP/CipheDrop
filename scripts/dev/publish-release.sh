#!/usr/bin/env bash
# Sign the CipherDrop program with the offline release key and publish it on
# the control server. Also places release.pub on alice, bob and carol, standing in
# for the organisation's machine image.
source "$(dirname "$0")/lib.sh"
STATE=/var/lib/cipherdrop-ca

say "USB stick: program -> offline root, which signs it with the release key"
dc cp control:/usr/local/bin/cipherdrop "$LAB/cipherdrop" 2>/dev/null
dc cp "$LAB/cipherdrop" root-ca:/tmp/cipherdrop 2>/dev/null
dc exec -T root-ca release-sign /tmp/cipherdrop

say "USB stick: signature back; publish program + signature on the control server"
dc cp root-ca:/tmp/cipherdrop.sig "$LAB/cipherdrop.sig" 2>/dev/null
dc cp root-ca:/ca-root/release.pub "$LAB/release.pub" 2>/dev/null
dc cp "$LAB/cipherdrop" control:"$STATE/release/cipherdrop" 2>/dev/null
dc cp "$LAB/cipherdrop.sig" control:"$STATE/release/cipherdrop.sig" 2>/dev/null

say "Machine image: put the release public key on the blank machines"
for n in alice bob carol; do dc cp "$LAB/release.pub" "$n":/usr/local/share/cipherdrop/release.pub 2>/dev/null; done
pass "release signed and published; alice, bob and carol can verify it"
