#!/usr/bin/env bash
# End-to-end check of a running stack, through the proxy, the way a browser
# uses it: page and CSRF token, batch, tus upload, scan, outbox handoff.
#
# Usage: scripts/smoke-test.sh https://upload.example.internal /srv/diode-upload
#
# It sends a clean file and the harmless EICAR antivirus test file, and
# checks that the first reaches the outbox with its sidecar and manifest and
# the second is quarantined. Run it as a user that can read DIODE_ROOT, for
# example with sudo. Use --insecure-tls for a self-signed test certificate.
# It leaves one clean test file (smoke-*.txt) and its .sha256 and manifest
# in the outbox for the diode to collect.
set -euo pipefail

insecure=()
if [ "${1:-}" = "--insecure-tls" ]; then insecure=(-k); shift; fi
origin="${1:?usage: $0 [--insecure-tls] ORIGIN DIODE_ROOT}"
root="${2:?usage: $0 [--insecure-tls] ORIGIN DIODE_ROOT}"
origin="${origin%/}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
jar="$work/cookies"
curl_() { curl -sS "${insecure[@]}" -b "$jar" -c "$jar" "$@"; }
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
fail() { echo "FAIL: $*" >&2; exit 1; }

curl_ -o "$work/page.html" "$origin/"
csrf="$(sed -n 's/.*<meta name="csrf-token" content="\([0-9a-f]*\)">.*/\1/p' "$work/page.html")"
[ -n "$csrf" ] || fail "no CSRF token in the page"
hdrs=(-H "Origin: $origin" -H "X-CSRF-Token: $csrf")

# upload NAME FILE BATCH -> prints the upload id
upload() {
  local name="$1" file="$2" batch="$3" size loc
  size="$(stat -c %s "$file")"
  loc="$(curl_ "${hdrs[@]}" -H "Tus-Resumable: 1.0.0" -H "Upload-Length: $size" \
    -H "Upload-Metadata: batch_id $(b64 "$batch"),filename $(b64 "$name")" \
    -X POST -o /dev/null -D - "$origin/api/v1/uploads/" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')"
  [ -n "$loc" ] || fail "upload of $name was not created"
  code="$(curl_ "${hdrs[@]}" -H "Tus-Resumable: 1.0.0" -H "Content-Type: application/offset+octet-stream" \
    -H "Upload-Offset: 0" -X PATCH --data-binary "@$file" -o /dev/null -w '%{http_code}' "$origin$loc")"
  [ "$code" = 204 ] || fail "PATCH for $name returned $code"
  echo "${loc##*/}"
}

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
clean="smoke-$stamp.txt"
printf 'diode upload smoke test %s\n' "$stamp" > "$work/clean"
# EICAR test string, assembled so this script is not itself flagged.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$work/eicar"

batch="$(curl_ "${hdrs[@]}" -H 'Content-Type: application/json' \
  -d '{"username":"smoketest","file_count":2}' "$origin/api/v1/batches" |
  sed -n 's/.*"batch_id":"\([^"]*\)".*/\1/p')"
[ -n "$batch" ] || fail "batch not created"
echo "batch $batch"
upload "$clean" "$work/clean" "$batch" >/dev/null
bad_id="$(upload "eicar-$stamp.com" "$work/eicar" "$batch")"

for _ in $(seq 1 120); do
  curl_ "${hdrs[@]}" -o "$work/status.json" "$origin/api/v1/batches/$batch"
  grep -q '"closed":true' "$work/status.json" && break
  sleep 2
done
cat "$work/status.json"; echo
grep -q '"closed":true' "$work/status.json" || fail "batch did not close"

out="$root/outbox"
want_sum="$(sha256sum "$work/clean" | cut -d' ' -f1)"
[ -f "$out/$clean" ] || fail "clean file not in the outbox"
[ "$(cat "$out/$clean.sha256")" = "$want_sum  $clean" ] || fail "sidecar does not match"
[ -f "$out/$batch.manifest.json" ] || fail "manifest missing"
grep -q '"audit_head"' "$out/$batch.manifest.json" || fail "manifest has no audit_head"
for f in "$out/$clean" "$out/$clean.sha256" "$out/$batch.manifest.json"; do
  [ "$(stat -c %a "$f")" = 644 ] || fail "$f mode is $(stat -c %a "$f"), want 644"
done
[ -f "$root/quarantine/$bad_id" ] || fail "EICAR file not in quarantine"
[ "$(stat -c %a "$root/quarantine/$bad_id")" = 640 ] || fail "quarantine file is not 0640"
ls "$out" | grep -q eicar && fail "EICAR file reached the outbox"
echo "PASS: clean file delivered, EICAR quarantined ($bad_id)"
