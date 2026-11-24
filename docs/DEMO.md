# Live demo script (4 terminals)

This is for the 10–12 minute presentation. The live part takes about 6
minutes; the rest is slides.

Every step that needs a 2FA code needs a **new** one, because codes work
once. When you're asked for a code, read the one your phone shows now; if
it's refused as already used, wait for the next one (at most 30 s). Talk
over the wait. It's a good moment to explain why codes are single-use.

---

## Before the presentation (10 minutes, at home)

Run this from the project folder. You'll choose the admin password and scan
a QR code with Google Authenticator.

```bash
make demo-setup
```

It deletes the old lab, creates the offline root CA, sets up the control
server, has the root sign the issuing CA, and publishes the signed program.
It also puts sample files in `~/documents` on alice, bob and carol.

If the code changed after you set up the lab, roll the new version out
without losing anything. It asks for your password and a code:

```bash
make update
```

Then open four terminal windows in the project folder, and make the font large.

| Terminal | Title it | Command |
|---|---|---|
| 1 | ROOT | `docker compose exec control bash` |
| 2 | ALICE (finance) | `docker compose exec alice bash` |
| 3 | BOB (legal) | `docker compose exec bob bash` |
| 4 | CAROL (hr) | `docker compose exec carol bash` |

Optional fifth terminal, MALLORY: `docker compose exec mallory bash`.

---

## Live

### 1. The root logs in (Terminal 1, about 30 s)

```bash
cipherdrop-ca console
```

Type the admin password and the code from your phone. The console opens
full screen:
- a header with server status
- **Registered devices**: state, online, registered, approved (2FA), IP, certificate expiry
- **Unverified devices on the network**, in red, only when there are any
- the messages and events log
- the `root>` command line at the bottom

The tables update by themselves.

> Say: "The control server holds the issuing CA. Its root CA is on an
> offline machine. Logging in needs the password and Google Authenticator,
> and the session locks after 15 idle minutes."

### 2. Pre-register alice (Terminal 1)

```text
slot add alice finance payroll exports
```

To choose the certificate's validity, add `--days N`, for example
`slot add alice finance payroll exports --days 180`. The default is 365 days.

The console switches to a plain screen showing
`sudo cipherdrop-bootstrap '...'` on one line, so it can be copied in one
piece. Copy it and press Enter to go back to the console.

> Say: "This one-time link holds the server's address, a 128-bit token, and
> the fingerprints of the server key and of the root CA. It works once and
> expires in 24 hours."

### 3. alice installs CipherDrop (Terminal 2, about 1 min)

Paste the line from step 2:

```bash
sudo cipherdrop-bootstrap 'cipherdrop://192.168.56.2:47480/enroll/...'
```

Watch the three steps:
1. **Download from the pinned server.** curl refuses any other key.
2. **Signature check.** OpenSSL verifies the Ed25519 release signature.
3. **Install and enrol.** It asks for a 2FA code: read the current one from your phone.

Terminal 1 now shows `ENROLLED alice (finance) ...`.

> Say: "alice's private key was generated on alice and never left it. The
> 2FA code was not sent as-is: it's an HMAC bound to this TLS session and to
> alice's key, so a relay attacker can't reuse it."

### 4. Enrol bob and carol (Terminals 1, 3, 4, about 1.5 min)

Same as steps 2 and 3. In Terminal 1:

```text
slot add bob legal contract archive
```

```text
slot add carol hr staff records
```

Then run each printed `sudo cipherdrop-bootstrap '...'` line in Terminal 3
(bob) and Terminal 4 (carol). Each one needs a fresh code.

### 5. Everyone opens the console (Terminals 2, 3, 4)

```bash
cipherdrop console
```

Each console opens full screen. At the top is **Devices on the network**
(state, IP, verify code, details). Under it is **Waiting for your answer**,
shown only while an offer is pending. Then come the messages and events log
and the command line. Each console broadcasts a signed beacon. A device turns green (`● bob legal ... verified`) once the two
machines have completed a mutual TLS handshake: each checked the other's
CA-issued certificate. Type `peers` to see the list again.

Terminal 1 shows `● alice (finance) is online ...`. Type `devices` there for
the full table: state, online, when it was registered and approved with
2FA, from which IP, and until when its certificate is valid.

> Say: "A beacon is only a claim. It must be signed by a key whose
> certificate chains to our root, and be fresh. The device is only trusted
> (green) after a two-way mutual TLS handshake proves it holds that key now."

### 6. Chat (about 30 s)

Terminal 3 (bob):

```text
msg alice hi alice, are the October payroll files ready?
```

Terminal 2 shows `[bob · legal] ... (signature verified)`, and bob sees
`✓ delivered (signed acknowledgement verified)`.

### 7. Send a folder while chatting (about 1.5 min)

Terminal 2 (alice):

```text
send bob documents/payroll
```

Terminal 3 (bob) sees the offer appear in the **Waiting for your answer**
table, with the manifest signature already verified:

```text
accept 1
```

Straight after, in Terminal 2, while the 50 MB file moves:

```text
msg bob sending now, check the CSV
```

alice sees `✓ sent 3 file(s) ...` and `bob's signed receipt verified`.

> Say: "One QUIC connection carries the chat and three file streams at the
> same time. alice signed a manifest with the SHA-256 of every file: proof of
> origin. bob checked every hash and signed a receipt: proof of delivery."

### 8. Show the proof (Terminals 2 and 1, about 1 min)

Terminal 2:

```text
evidence
```

Then verify the receipt, using the file name `evidence` printed:

```text
verify <id>.receipt.json
```

Terminal 1:

```text
slot list
```

```text
audit 10
```

> Say: "The receipt is an Ed25519 signature by bob's CA-certified key. bob
> cannot later deny receiving these exact files. The audit log is
> hash-chained and signed, so the admin's actions can't be quietly edited
> either."

### 8b. Optional: renew a certificate (about 1 min)

Terminal 1:

```text
renew alice --days 730
```

Then run the printed `sudo cipherdrop-bootstrap '...'` line in Terminal 2,
exactly as for enrolment, with a fresh code. alice keeps her name and
department, gets a **new key** and a 730-day certificate, and the old
certificate is revoked as *superseded* in OpenSSL's CA database.

> Say: "Renewal rotates the key. alice proves it is really her by signing
> the request with her current key, which works even after the certificate
> has expired, and the admin approves with 2FA."

### 9. Attacks (about 1 min)

**Live and visual: a fake device.** In the Mallory terminal
(`docker compose exec mallory bash`):

```bash
rogue -mode beacon -name bob -for 60s
```

Every console and the root show a red `✗ UNVERIFIED device claiming "bob"
... certificate not trusted`, while the real bob stays green. Try `peers` in
alice and `devices` in root.

**Replay a real beacon:**

```bash
rogue -mode replay -name carol
```

It appears in red as `replayed beacon (nonce already seen)`.

**All the other attacks at once:**

Run this from a fifth terminal on the Mac, with your admin password in the
quotes. It runs all six attacks:

```bash
CIPHERDROP_ADMIN_PASSWORD='your-admin-password' make attacks
```

To keep it short, narrate two of them:
- Mallory pretending to be bob: refused as "unknown authority".
- Mallory with a stolen link: 5 wrong guesses lock it.

For a single live one, Mallory runs a fake control server and alice's
bootstrap refuses it. That's attack 3 in `make attacks`.

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| "2FA code is wrong, expired or already used" | wait for the next code on the phone |
| `cannot listen: ... address already in use` | a console is already open on that machine; type `quit` there |
| enrolment link "already used" or "locked" | `slot add` a new one with the same name (allowed after a lock) |
| `slot add` says the device "has an open slot" | its earlier link still works; if it's lost, `slot cancel <name>`, then `slot add` again |
| a device shows `renew soon` or `cert expired` | Terminal 1: `renew <name>`, then run the printed line on that device |
| a console says the certificate expired | same: the admin runs `renew <name>`; renewal works after expiry |
| a device stays yellow ("checking") | wait 5 s; if it turns red, its handshake failed and the reason is shown |
| the messages box is full of old lines | type `clear` (or press Ctrl-L); received files and signed evidence are kept |
| the full-screen layout looks broken (very small window, unusual terminal) | make the window bigger, or use `cipherdrop console --plain` / `cipherdrop-ca console --plain` |
| everything is broken | `make demo-setup` again (about 3 minutes) |
