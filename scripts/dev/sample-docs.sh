#!/usr/bin/env bash
# Put sample documents in ~/documents on alice, bob and carol, for sending
# during the demo. Rebuilding a machine resets its home folder (only the
# identity in /var/lib/cipherdrop is kept), so `make update` runs this too.
# Existing files are left alone.
source "$(dirname "$0")/lib.sh"

add() { # add MACHINE PATH CONTENT-COMMAND
  dc exec -T "$1" sh -c "mkdir -p \"\$(dirname ~/$2)\" && [ -e ~/$2 ] || { $3 > ~/$2; }"
}
add alice documents/payroll/october.csv 'printf "employee,month,net\nE001,2026-10,4210.55\nE002,2026-10,3988.10\n"'
add alice documents/q3-summary.txt      'echo "Q3 payroll summary: approved"'
add alice documents/payroll/scans.bin   'head -c 52428800 /dev/urandom'
add bob   documents/nda-draft.txt       'printf "MUTUAL NON-DISCLOSURE AGREEMENT (draft 2)\n"'
add bob   documents/contracts/vendor-a.txt 'printf "Vendor A service contract, signed copy\n"'
add carol documents/onboarding.txt      'printf "Onboarding checklist: laptop, badge, accounts\n"'
add carol documents/staff-list.csv      'printf "id,name,team\n1,Alice,Finance\n2,Bob,Legal\n3,Carol,HR\n"'
pass "sample documents in ~/documents on alice, bob and carol"
