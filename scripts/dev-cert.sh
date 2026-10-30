#!/bin/sh
# Make a self-signed certificate for local testing only.
# Usage: scripts/dev-cert.sh upload.localtest.me
set -eu
host="${1:?usage: $0 <hostname>}"
dir="$(dirname "$0")/../deploy/tls"
openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
  -keyout "$dir/upload.key" -out "$dir/upload.crt" \
  -subj "/CN=$host" -addext "subjectAltName=DNS:$host"
chmod 644 "$dir/upload.crt"
chmod 644 "$dir/upload.key" # the proxy runs as uid 101; tighten with chown in production
echo "Wrote $dir/upload.crt and $dir/upload.key for $host (valid 30 days)."
