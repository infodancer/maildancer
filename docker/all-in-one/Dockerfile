# syntax=docker/dockerfile:1
#
# All-in-one image: the whole maildancer stack in a single container, supervised
# by s6-overlay. This is the common, obvious deployment -- one image to reason
# about -- as opposed to the per-component images (one binary each) that exist
# for operators who want to isolate each daemon.
#
# Every binary is built from the same monorepo commit, so there is no version
# skew between session-manager and the daemons that talk to it.
#
# Privilege separation is unchanged: it is uid/gid-based (SysProcAttr.Credential),
# not container-based. session-manager spawns mail-session and smtpd spawns its
# protocol-handler / mail-deliver children as per-user/per-domain uids, so this
# container must run as root (or with CAP_SETUID + CAP_SETGID). That is the
# expected posture for an appliance mail image.
#
# Build context is the repository root.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
# infodancer/logging is an external module; supply a token for the (possibly
# private) fetch if one is mounted, otherwise fall back to anonymous.
RUN --mount=type=secret,id=github_token \
    TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    if [ -n "$TOKEN" ]; then \
        git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"; \
    fi; \
    GOPRIVATE=github.com/infodancer/* go mod download

COPY . .
# Build every daemon and helper into /out. The spawned helpers (mail-session,
# mail-remote) must sit next to their spawners; the config references
# /mail-session and queue-manager is invoked with --binary /mail-remote.
RUN set -eux; \
    for c in session-manager mail-session smtpd pop3d imapd \
             queue-manager mail-remote webadmin auth-oidc userctl; do \
        CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o "/out/${c}" "./cmd/${c}"; \
    done

# ---------------------------------------------------------------------------

FROM alpine:3.21

# s6-overlay: proper PID1 (zombie reaping -- smtpd and the session daemons fork
# per-connection children), declarative startup ordering, and clean signal
# forwarding for graceful shutdown.
ARG S6_OVERLAY_VERSION=3.2.0.2
ARG TARGETARCH

RUN apk add --no-cache ca-certificates xz tzdata

ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp/s6-noarch.tar.xz
RUN tar -C / -Jxpf /tmp/s6-noarch.tar.xz && rm /tmp/s6-noarch.tar.xz
# s6 release artifacts are named by uname -m, not Docker's TARGETARCH.
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp/s6-arch.tar.xz
RUN test "${TARGETARCH:-amd64}" = "amd64" \
    && tar -C / -Jxpf /tmp/s6-arch.tar.xz && rm /tmp/s6-arch.tar.xz

# Daemons at / to match the config (mail_session_cmd = "/mail-session") and the
# queue-manager --binary /mail-remote contract.
COPY --from=builder /out/ /

# s6-rc service tree.
COPY docker/all-in-one/rootfs/ /

# Let services wait a little for their dependencies' sockets at boot.
ENV S6_KEEP_ENV=1 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0

EXPOSE 25 110 143 465 587 993 995 8080 9100 9102

ENTRYPOINT ["/init"]
