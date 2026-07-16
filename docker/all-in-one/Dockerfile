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
# not container-based. session-manager spawns mail-session per-user, and smtpd's
# listener stays root -- it binds 25/465/587 and spawns a protocol-handler per
# connection dropped to the smtpd service account (uid 903, group mailsvc) --
# so this container must run as root (or with CAP_SETUID + CAP_SETGID). That is
# the expected posture for an appliance mail image. pop3d and imapd, which spawn
# nothing and reach storage only through session-manager's gRPC socket, run as
# the fixed service accounts declared below (see internal/admin for the ids);
# queue-manager runs as queued, and mail-remote inherits that via exec.
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
             queue-manager mail-remote webadmin auth-oidc userctl tlsstage; do \
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

# Service accounts with fixed ids (mirrored as constants in internal/admin,
# next to the uid/gid allocator's 10000 floor -- these must stay below it).
# mailsvc is the shared daemon group; cfgread names the config-tree read gid
# (queued joins it: queue-manager reads per-domain outbound routing config
# from the webadmin:cfgread 0640 config tree). pop3d/imapd and queue-manager drop
# root at exec and smtpd's per-connection handlers drop to the smtpd account;
# webadmin stays root until its own issue.
RUN addgroup -S -g 900 mailsvc \
    && addgroup -S -g 906 cfgread \
    && adduser -S -D -H -u 901 -G mailsvc -s /sbin/nologin pop3d \
    && adduser -S -D -H -u 902 -G mailsvc -s /sbin/nologin imapd \
    && adduser -S -D -H -u 903 -G mailsvc -s /sbin/nologin smtpd \
    && adduser -S -D -H -u 904 -G mailsvc -s /sbin/nologin queued \
    && adduser -S -D -H -u 905 -G mailsvc -s /sbin/nologin webadmin \
    && adduser queued cfgread

# Daemons at / to match the config (mail_session_cmd = "/mail-session") and the
# queue-manager --binary /mail-remote contract.
COPY --from=builder /out/ /

# Let the unprivileged daemons bind their standard low ports (110/995 and
# 143/993); the in-container ports are unchanged.
RUN apk add --no-cache libcap \
    && setcap 'cap_net_bind_service=+ep' /pop3d \
    && setcap 'cap_net_bind_service=+ep' /imapd

# s6-rc service tree.
COPY docker/all-in-one/rootfs/ /

# Let services wait a little for their dependencies' sockets at boot.
ENV S6_KEEP_ENV=1 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0

EXPOSE 25 110 143 465 587 993 995 8080 9100 9102

ENTRYPOINT ["/init"]
