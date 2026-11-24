.PHONY: help build build-linux test lab-up lab-down lab-reset demo-setup update sample-docs provision ping transfer discovery renew attacks capture check check-reset

# Static binaries, no C toolchain needed. Version stamps are not embedded:
# releases are identified by their SHA-256 and Ed25519 signature instead.
GOBUILD = CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"
LINUX_ARCH ?= amd64

help:
	@echo "make build       compile cipherdrop and cipherdrop-ca for this computer into bin/"
	@echo "make build-linux compile Linux binaries into bin/linux-\$$LINUX_ARCH/ (LINUX_ARCH=arm64 for ARM)"
	@echo "make test        Go unit tests: crypto, handshakes, enrolment attacks (no Docker)"
	@echo "make lab-up      build images, start root-ca, control, alice, bob, carol, mallory"
	@echo "make provision   zero-trust provisioning: root -> issuing CA -> signed release -> 2FA enrolment"
	@echo "make demo-setup  prepare the live demo with YOUR password and phone (see docs/DEMO.md)"
	@echo "make ping        alice -> bob over QUIC + mutual TLS 1.3 (X25519 key exchange)"
	@echo "make transfer    alice sends a folder to bob while chatting; receipt checked with OpenSSL"
	@echo "make attacks     6 attacks (impersonation, fake server, tampering, stolen link, audit edit) must fail"
	@echo "make capture     save a pcap of the handshake into docs/evidence/ (KEYLOG=1 to decrypt)"
	@echo "make update      rebuild and roll the new signed program out to the demo lab (keeps everything)"
	@echo "make sample-docs put sample files in ~/documents on alice, bob and carol"
	@echo "make discovery   beacons + two-way verification; fake/replayed beacons shown in red"
	@echo "make renew       certificate renewal: new key, same name, old cert revoked as superseded"
	@echo "make check       everything, in a SEPARATE test lab (cipherdrop-test, 192.168.57.x)"
	@echo "make check-reset delete the test lab"
	@echo "make lab-down    stop the lab (keeps keys, CA and audit log)"
	@echo "make lab-reset   stop the lab and DELETE every key, the CAs and the audit log"

build:
	$(GOBUILD) -o bin/cipherdrop ./cmd/cipherdrop
	$(GOBUILD) -o bin/cipherdrop-ca ./cmd/cipherdrop-ca

build-linux:
	GOOS=linux GOARCH=$(LINUX_ARCH) $(GOBUILD) -o bin/linux-$(LINUX_ARCH)/cipherdrop ./cmd/cipherdrop
	GOOS=linux GOARCH=$(LINUX_ARCH) $(GOBUILD) -o bin/linux-$(LINUX_ARCH)/cipherdrop-ca ./cmd/cipherdrop-ca

test:
	go vet ./...
	go test -count=1 ./...

lab-up:
	docker compose up -d --build root-ca control alice bob carol mallory

lab-down:
	docker compose down

lab-reset:
	docker compose down -v --remove-orphans
	rm -rf .lab/cipherdrop

demo-setup:
	./scripts/dev/demo-setup.sh

update:
	./scripts/dev/update.sh

sample-docs:
	./scripts/dev/sample-docs.sh

discovery:
	./scripts/dev/discovery.sh

renew:
	./scripts/dev/renew.sh

provision:
	./scripts/dev/provision.sh

transfer:
	./scripts/dev/transfer.sh

ping:
	./scripts/dev/ping.sh

attacks:
	./scripts/dev/attacks.sh

capture:
	./scripts/dev/capture.sh

# The automated checks run in their own Compose project and subnet, so they
# never disturb the demo lab prepared with `make demo-setup`.
TESTLAB = CIPHERDROP_PROJECT=cipherdrop-test CIPHERDROP_NET=192.168.57

check: test
	$(TESTLAB) docker compose up -d --build root-ca control alice bob carol mallory
	$(TESTLAB) ./scripts/dev/provision.sh
	$(TESTLAB) ./scripts/dev/ping.sh
	$(TESTLAB) ./scripts/dev/transfer.sh
	$(TESTLAB) ./scripts/dev/discovery.sh
	$(TESTLAB) ./scripts/dev/renew.sh
	$(TESTLAB) ./scripts/dev/attacks.sh

check-reset:
	$(TESTLAB) docker compose down -v --remove-orphans
	rm -rf .lab/cipherdrop-test
