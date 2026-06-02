#!/bin/sh
# Generate a self-signed certificate for local-dev TLS (STARTTLS / implicit TLS).
# Needed for authenticated submission and the 465/995/993 ports. NOT for production.
#
#   ./deploy/gen-dev-certs.sh [hostname]
#
# Then uncomment [server.tls] in deploy/config/config.toml and `docker compose up -d`.
set -e

HOST="${1:-mail.example.com}"
DIR="$(dirname "$0")/certs"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$DIR/mail.key" -out "$DIR/mail.pem" \
  -subj "/CN=$HOST" >/dev/null 2>&1

chmod 644 "$DIR/mail.key"
echo "Wrote $DIR/mail.pem and $DIR/mail.key for CN=$HOST (self-signed, 365d)."
echo "Now uncomment [server.tls] in deploy/config/config.toml and restart the stack."
