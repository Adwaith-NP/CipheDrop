# Try CipherDrop yourself

Run every command from the project folder, with Docker Desktop running.

```bash
cd CipherDrop
```

There are two labs, so testing never breaks your demo:

| Lab | Compose project | Network | Used by |
|---|---|---|---|
| demo lab | `cipherdrop` | 192.168.56.x | `make demo-setup`, `make provision`, your terminals |
| test lab | `cipherdrop-test` | 192.168.57.x | `make check` only |

---

## Option A: every automated check (about 8 minutes, test lab)

```bash
make check
```

This runs:
- the unit tests
- zero-trust enrolment of alice, bob and carol
- the secure channel test
- a 50 MB folder transfer with chat and an OpenSSL-checked receipt
- discovery with Mallory's fake and replayed beacons
- the six attacks

Your demo lab is not touched. To delete the test lab afterwards:

```bash
make check-reset
```

---

## Option B: hands-on without your phone (demo lab)

Codes are generated for you:

```bash
make lab-reset
```

```bash
make lab-up
```

```bash
make provision
```

Then open a terminal per machine:

```bash
docker compose exec alice bash
```

```bash
docker compose exec bob bash
```

In each one, start the console:

```bash
cipherdrop console
```

| Where | Type | What happens |
|---|---|---|
| any console | `peers` | devices on the network: green = verified both ways, red = NOT verified |
| bob | `msg alice hello` | alice sees it, signature verified; bob gets a signed acknowledgement |
| alice | `send bob /etc/hostname` | bob gets an offer |
| bob | `accept 1` | the file arrives; alice gets bob's signed receipt |
| alice | `evidence`, then `verify <file>` | proof of origin and proof of delivery |

To see a red, unverified device:

```bash
docker compose exec mallory rogue -mode beacon -name bob -for 60s
```

---

## Option C: the full demo with your own phone (demo lab)

This is the presentation flow, with your own admin password and Google
Authenticator. Follow [DEMO.md](DEMO.md). It starts with:

```bash
make demo-setup
```

After a code change, keep everything and roll the new program out:

```bash
make update
```

---

## When you're done

Stop the demo lab but keep the keys:

```bash
make lab-down
```

Delete the demo lab:

```bash
make lab-reset
```
