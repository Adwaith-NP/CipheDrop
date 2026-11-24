# syntax=docker/dockerfile:1.7
# Two lab images:
#   full   CipherDrop tools + OpenSSL PKI scripts (root-ca, control, mallory)
#   blank  a fresh organisation machine: only the bootstrap script (alice, bob)

FROM golang:1.27-trixie AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY test ./test
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/cipherdrop ./cmd/cipherdrop && \
    go build -trimpath -ldflags="-s -w" -o /out/cipherdrop-ca ./cmd/cipherdrop-ca && \
    go build -trimpath -ldflags="-s -w" -o /out/rogue ./test/attacks/rogue

# Debian 13 ships OpenSSL 3.5 (Ed25519 certificates, `pkeyutl -rawin`).
FROM debian:trixie-slim AS base
# Fetch packages over HTTPS (a host-wide HTTP proxy cannot interfere, and
# transport is encrypted as well as signature-checked). The slim image has no
# CA bundle yet, so borrow the build stage's for this one step.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /tmp/bootstrap-ca.crt
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::https::CAInfo=/tmp/bootstrap-ca.crt update \
 && apt-get -o Acquire::https::CAInfo=/tmp/bootstrap-ca.crt install -y --no-install-recommends \
      openssl ca-certificates curl iproute2 iputils-ping procps tcpdump sudo less nano \
 && rm -rf /var/lib/apt/lists/* /tmp/bootstrap-ca.crt
RUN useradd --uid 1000 --create-home --shell /bin/bash cipherdrop \
 && install -d -o cipherdrop -g cipherdrop -m 0700 /var/lib/cipherdrop \
 && install -d -m 0755 /usr/local/share/cipherdrop
ENV CIPHERDROP_HOME=/var/lib/cipherdrop
CMD ["sleep", "infinity"]

FROM base AS blank
COPY scripts/bootstrap/cipherdrop-bootstrap.sh /usr/local/sbin/cipherdrop-bootstrap
# Least privilege: the user may run exactly one command as root, the
# bootstrap. (Lab image: no sudo password; a real machine would ask for one.)
RUN chmod 0755 /usr/local/sbin/cipherdrop-bootstrap \
 && echo 'cipherdrop ALL=(root) NOPASSWD: /usr/local/sbin/cipherdrop-bootstrap' > /etc/sudoers.d/cipherdrop \
 && chmod 0440 /etc/sudoers.d/cipherdrop
USER cipherdrop
WORKDIR /home/cipherdrop

FROM base AS full
COPY --from=build /out/cipherdrop /out/cipherdrop-ca /out/rogue /usr/local/bin/
COPY scripts/pki/ /usr/local/share/cipherdrop/pki/
RUN chmod 0755 /usr/local/share/cipherdrop/pki/*.sh \
 && for s in root-init root-sign-issuing release-sign; do ln -s /usr/local/share/cipherdrop/pki/$s.sh /usr/local/bin/$s; done \
 && install -d -o cipherdrop -g cipherdrop -m 0700 /ca-root /var/lib/cipherdrop-ca
ENV CA_HOME=/ca-root \
    CIPHERDROP_CA_HOME=/var/lib/cipherdrop-ca \
    CIPHERDROP_PKI_DIR=/usr/local/share/cipherdrop/pki
USER cipherdrop
WORKDIR /home/cipherdrop
