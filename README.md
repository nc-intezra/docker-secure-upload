# docker-secure-upload

A self-contained, container-based web service that takes files from users,
virus-scans them, fingerprints them with SHA-256 and hands them to a data
diode's watched folder.

Design spec: [Diode Upload Service: v1 design spec](https://claude.ai/artifact/NarfJQZ4dKew8XsEr38ChR)

## Status

| Stage | Scope | State |
| --- | --- | --- |
| 1 | Upload page, resumable uploads, SHA-256, ClamAV scanning, outbox handoff, audit log, hardened compose stack | **this commit** |
| 2 | Admin site: history, quarantine list, release/delete/rescan, quarantine switch, retention | next PR |
| 3 | Rate limiting, Prometheus/Zabbix `/metrics`, startup oversize self-test, remaining hardening | PR after that |

## How it works

```
browser ──TLS──▶ nginx ──▶ upload-api (Go) ──▶ /data/incoming/<id>
                                 │                    │
                                 │   zSCAN by path    ▼
                                 └────────────▶ clamd (read-only incoming/ and tmp/ only)
                                                      │
          passed / unscanned ──▶ /data/outbox/  ◀─────┘   (atomic rename + .sha256 + batch manifest)
          infected           ──▶ /data/quarantine/ (or deleted when quarantine is off)
          scan error / limit ──▶ /data/quarantine/ (held) ──operator release──▶ /data/outbox/
```

1. The page loads with a session cookie (`__Host-sid`) and a CSRF token.
2. The user enters a username and drops or picks files. The page creates a
   batch, then uploads each file with the [tus 1.0.0](https://tus.io/protocols/resumable-upload)
   protocol in 64 MiB chunks. A dropped connection resumes from the server's
   offset.
3. The server computes SHA-256 as chunks arrive. After every chunk the
   hasher's internal state is saved with the upload record, so even a
   service restart mid-upload does not require re-reading data.
4. A completed file is scanned by clamd **by path** from a read-only mount,
   so clamd's stream size limit does not apply.
5. The result decides the end state (see below). Passed files are moved into
   the outbox in one atomic rename; the `.sha256` sidecar follows; the batch
   manifest is written last.
6. Every step is written to a hash-chained audit log.

### End states

| Scan result | End state | Where the file goes |
| --- | --- | --- |
| `OK`, file at or under `CLAMD_MAX_SCAN_SIZE` | passed | outbox |
| `OK` but file larger than `CLAMD_MAX_SCAN_SIZE` | held (policy `hold`, the default) or unscanned (policy `pass`) | quarantine/ until released, or outbox flagged in the manifest |
| `Heuristics.Limits.Exceeded.MaxFileSize` / `.MaxScanSize` | held (policy `hold`) or unscanned (policy `pass`) | quarantine/ until released, or outbox flagged in the manifest |
| `Heuristics.Limits.Exceeded.MaxRecursion` / `.MaxFiles` / `.MaxScanTime` | held | quarantine/ |
| any other `FOUND` (including `Heuristics.Encrypted.*`) | quarantined, or deleted if `QUARANTINE_ENABLED=false` | quarantine/ or removed |
| `ERROR`, timeout, unexpected reply | held | quarantine/ |

ClamAV cannot scan files over about 4 GB. With the default
`OVERSIZE_POLICY=hold`, such files never reach the outbox until an operator
releases them (see [Held files](#held-files)). Held files can be released;
infected (quarantined) files cannot.

The service never scans until clamd has passed an EICAR self-test, which is
repeated hourly. If clamd is unreachable, files wait in the queue instead of
being held.

## Outbox format

By default each file keeps the name it had on the sender's computer:

```
outbox/
  Quarterly Report (final).pdf
  Quarterly Report (final).pdf.sha256          # "<hex>  <name>", works with sha256sum -c
  20261103T141502Z-jsmith-a3f9c1.manifest.json
```

If the sender ticks **Add the batch ID and my username to file names**, names
start with the batch ID and a sequence number instead:
`20261103T141502Z-jsmith-a3f9c1_001_Quarterly Report (final).pdf`. The batch ID,
username and original name are always in the manifest and the audit log.

Names are changed only where they must be:

- any directory part is dropped
- characters illegal on Linux or Windows (control characters and `< > : " / \ | ? *`) become `_`
- leading dots and spaces, trailing dots and spaces, are removed
- Windows device names (`CON`, `NUL`, `COM1` ...) get a leading `_`
- invisible and direction-changing Unicode characters (format characters
  such as the right-to-left override, zero-width spaces and the byte-order
  mark) become `_`, so `invoice<RLO>fdp.exe` cannot pass for a PDF
- names over 180 bytes are shortened, keeping the extension
- names ending in `.sha256` or `.manifest.json` get a trailing `_`, so an
  upload can never pass for a sidecar or manifest the service wrote

Spaces, accented and non-Latin letters, brackets and other punctuation are
kept, so scripts on the receiving side must quote file names.

Without the prefix, two uploads can have the same name. A file is never
written over another: if a file with the same name, or its `.sha256`, is
still in the outbox, the new file waits (checked every 10 seconds) until the
diode has collected both. If they are still there after an hour, the new
file is held instead. The receiving side decides what happens when a second
file with the same name arrives there.

The manifest lists every passed file with its outbox name, original name,
size, SHA-256, `scan_status` (`clean`, `unscanned` or `released`) and
signature database. Withheld files are only counted; their names never
cross the diode. `audit_head` holds the sequence number and hash of the
newest audit event when the manifest was written: keep manifests on the
receiving side and a later rewrite of the upload host's audit log can be
detected.

A file released after its batch manifest has already gone gets a manifest of
its own, `<batch>.release-<id>.manifest.json`, with a `release` block saying
who released it, why, and why it was held.

## Prerequisites

- A Linux host (written for Ubuntu Server) with at least 4 CPU cores and
  6 GB RAM (the compose limits add up to about 5 GB, mostly clamd), plus disk for in-flight uploads
  and quarantine on the same filesystem as the diode's watched folder.
- **Docker Engine with the Compose plugin from Docker's own packages.**
  `docker compose version` must report v2.

> **Do not use the Docker snap** (`snap install docker`, or the "docker"
> option offered by the Ubuntu Server installer). The snap is sandboxed to
> your home folder: it cannot read `compose.yaml` in `/opt`, `/srv` or
> `/root`, and it cannot bind-mount `DIODE_ROOT`. The usual symptom is
> `no configuration file provided: not found` even when you run it from the
> folder that holds `compose.yaml`. `which docker` printing
> `/snap/bin/docker` means the snap is in use.

### Installing Docker Engine on Ubuntu

```sh
# 1. Remove the snap if it is installed (this also deletes anything it stored).
sudo snap remove --purge docker

# 2. Add Docker's apt repository.
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list

# 3. Install Engine, CLI, Buildx and Compose.
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 4. Check.
which docker              # /usr/bin/docker
docker compose version    # Docker Compose version v2.x
sudo docker run --rm hello-world
```

If a step fails, Docker's current instructions are at
<https://docs.docker.com/engine/install/ubuntu/>.

To run `docker` without `sudo`, add your user to the `docker` group
(`sudo usermod -aG docker "$USER"`, then log out and back in). Membership
of that group is equivalent to root on the host, so grant it only to
administrators of this server.

## Host layout

The diode's watched folder and the staging folders must be on **one
filesystem** so moves are atomic. The service refuses to start otherwise,
and also refuses if a staging folder is inside the outbox.

```
/srv/diode-upload/          # DIODE_ROOT, mounted at /data in the app
  outbox/                   # the folder the diode watches (2-second settle time)
  incoming/                 # files being received and scanned (clamd reads these)
  quarantine/               # held and infected files
  tmp/                      # scratch space, emptied at startup (clamd reads these)
```

Create all four before the first start. clamd mounts `incoming/` and `tmp/`
directly; if they do not exist Docker creates them owned by root and the app
cannot write to them.

```sh
sudo install -d -m 0750 -o 65532 -g 65532 /srv/diode-upload \
     /srv/diode-upload/incoming /srv/diode-upload/quarantine /srv/diode-upload/tmp
sudo install -d -m 2775 -o 65532 -g <diode-group> /srv/diode-upload/outbox
```

The app runs as uid 65532. Staging and quarantine files are mode 0640 and
their folders 0750: clamd reads them through group 65532, and nothing else
on the host can. Files, sidecars and manifests in `outbox/` are mode 0644 so
the diode can read them; the diode needs write access to `outbox/` to remove
what it has collected.

## Running

Install Docker Engine first (see [Prerequisites](#prerequisites)), then from the
repository folder:

```sh
cp .env.example .env                                   # set PUBLIC_ORIGIN and DIODE_ROOT
head -c 48 /dev/urandom | base64 > secrets/csrf_key && chmod 600 secrets/csrf_key
# put upload.crt / upload.key in deploy/tls/ (scripts/dev-cert.sh for a local test)
docker compose up -d --build
docker compose logs -f app                             # wait for "clamd self-test passed"
```

clamd downloads its signatures on first start, which can take several
minutes; uploads are accepted meanwhile and scanned once it is ready.

Useful commands:

```sh
curl -s http://127.0.0.1:9100/readyz                   # 200 once clamd is proven and disk is above reserve
docker compose exec app diode-upload version           # running version
docker compose exec app diode-upload verify-audit      # check the audit hash chain
sudo scripts/smoke-test.sh https://upload.example.internal /srv/diode-upload
                                                       # send a clean file and EICAR end to end
```

`smoke-test.sh` leaves one small `smoke-*.txt` file, its `.sha256` and its
manifest in the outbox. Add `--insecure-tls` before the address when testing
with a self-signed certificate.

## Held files

A file is held when clamd could not give a clear answer: it is too large to
scan (with `OVERSIZE_POLICY=hold`), an archive exceeds the nesting or
file-count limits, or the scan failed. Held files wait in `quarantine/`
and the sender's page shows "Held for administrator review". Until the admin
site arrives, operators handle them from the host:

```sh
docker compose exec app diode-upload held
#   ID                                STATE        USER    SIZE         RECEIVED           NAME         REASON
#   3f1c...                           held         jsmith  6442450944   2026-11-04 10:12Z  backup.tar   file is larger than ClamAV can scan ...

docker compose exec app diode-upload release 3f1c... --by "A. Admin" --reason "vendor image, checked with offline AV"
docker compose exec app diode-upload delete  3f1c... --by "A. Admin" --reason "sender asked to drop it"
```

- `release` reads the file again and refuses if its SHA-256 no longer
  matches what the user sent. It then moves the file to the outbox under
  the name it would have had, with its `.sha256`. If the batch manifest has
  already gone, a release manifest follows.
- Infected (`quarantined`) files can only be deleted, never released.
- `--by` and `--reason` are required and recorded in the audit log
  (`upload.released`, `upload.discarded`).
- The commands talk to the running service over a unix socket inside the
  app container (`/tmp/diode-upload.sock`, mode 0600, only accepted from the
  service's own user), so they need Docker access on the host and nothing is
  exposed on the network.

## Limits

To stop one client tying up the staging disk, the service caps what a
browser session, and a client address across all its sessions, may have in
progress at once:

| | Per session | Per address |
| --- | --- | --- |
| Batches not yet finished | 10 | 30 |
| Files still uploading | 20 | 60 |
| Bytes still to arrive | 100 GiB (2 × `MAX_FILE_SIZE`) | 300 GiB |

A request over a cap gets `429 Too Many Requests`. The upload page waits and
retries on its own ("Waiting for your earlier uploads to finish"). An upload
that receives nothing for `UPLOAD_EXPIRY` (1 hour) is dropped, and a batch
with no uploads is deleted after the same time. nginx also limits upload
creation to 2 per second per address (burst 20). If many users share one
address (a terminal server or NAT), raise the `IP_MAX_*` settings.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `no configuration file provided: not found` | The Docker snap is in use. See [Prerequisites](#prerequisites). |
| `state store: mkdir /state/batches: permission denied` | The `state` volume was created by an image from before v0.5.1, so it is owned by root. If nothing has been uploaded yet: `docker compose down`, then `docker volume rm diode-upload_state`, then `docker compose up -d --build`. To keep existing data instead: `docker run --rm -v diode-upload_state:/state busybox chown -R 65532:65532 /state` |
| Upload page says `Could not start: request did not come from this site` | `PUBLIC_ORIGIN` does not exactly match the address in the browser (scheme, host name and port all count). `docker compose logs app \| grep "request rejected"` shows the `origin` the browser sent next to `expected_origin`. In the browser's developer console, `location.origin` prints the value to use. Set `PUBLIC_ORIGIN` to it in `.env` (no trailing slash), run `docker compose up -d app`, then reload the page. Users must all use that one address. |
| Upload page says `reload the page and try again` | The page's session cookie or CSRF token is missing or no longer valid, for example because `secrets/csrf_key` was changed while the page was open, or the browser blocked the cookie. Reload the page. The log line `request rejected` shows `reason` `no_session` or `bad_csrf`. |
| `storage layout: ... permission denied` or `outbox: ... no such file or directory` | `DIODE_ROOT` or its `outbox/` is missing or not writable by uid 65532. See [Host layout](#host-layout). |
| `storage layout: ... (the folder must belong to uid 65532)` | `incoming/`, `quarantine/` or `tmp/` under `DIODE_ROOT` was created by Docker or by root. `sudo chown 65532:65532 "$DIODE_ROOT"/{incoming,quarantine,tmp}`, then `docker compose up -d`. |
| A file shows "Waiting for your earlier uploads to finish" | A [limit](#limits) is reached for that browser or computer. It starts by itself when earlier uploads finish. `docker compose logs app \| grep "refused: limit"` shows which cap. |
| A file shows "Held for administrator review" | See [Held files](#held-files). |
| Uploads stay at "Scanning" for a long time after the first start | clamd is still downloading signatures. `docker compose logs -f clamd`; scanning starts after the app logs `clamd self-test passed`. |

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | (required) | Exact origin users browse to; checked against `Origin` on every write |
| `TRUSTED_PROXY_CIDRS` | none | Peers allowed to set `X-Real-IP` |
| `DATA_DIR` / `OUTBOX_DIR` / `STATE_DIR` | `/data` / `$DATA_DIR/outbox` / `/state` | |
| `MAX_FILE_SIZE` | `50GiB` | |
| `CHUNK_SIZE` | `64MiB` | nginx `client_max_body_size` for the uploads path must be this + 1 MiB |
| `DISK_RESERVE` | `10GiB` | Free space kept beyond all unfinished uploads |
| `UPLOAD_EXPIRY` | `1h` | An upload that receives nothing for this long is dropped; so is a batch with no activity |
| `CLAMD_ADDR` | `clamd:3310` | |
| `CLAMD_PATH_PREFIX` | `$DATA_DIR` | Where clamd sees `DATA_DIR` (for an external clamd) |
| `CLAMD_MAX_SCAN_SIZE` | `4000M` | Must match `MaxScanSize` in `clamd.conf` |
| `SCAN_CONCURRENCY` / `SCAN_TIMEOUT` | `2` / `2h` | |
| `OVERSIZE_POLICY` | `hold` | `hold` (operator releases), `pass` (sent flagged unscanned) or `reject` (refused at upload) |
| `QUARANTINE_ENABLED` | `true` | `false` deletes infected files instead |
| `MAX_BATCH_FILES` | `500` | |
| `SESSION_MAX_OPEN_BATCHES` / `_OPEN_UPLOADS` / `_RESERVED` | `10` / `20` / 2 × `MAX_FILE_SIZE` | Per browser session, see [Limits](#limits); `0` = no cap |
| `IP_MAX_OPEN_BATCHES` / `_OPEN_UPLOADS` / `_RESERVED` | 3 × the session values | Per client address |
| `CONTROL_SOCKET` | `/tmp/diode-upload.sock` | Socket for the held-file commands; `off` disables them |
| `INSTRUCTIONS_FILE` | `/config/instructions.md` | Headings, lists, paragraphs and `**bold**`; everything is HTML-escaped |
| `CSRF_KEY_FILE` | `/run/secrets/csrf_key` | At least 32 bytes |
| `HEALTH_ADDR` | `0.0.0.0:9100` | `/healthz`, `/readyz` (metrics join in stage 3) |

## Security notes

- **No third-party Go modules.** The tus server, clamd client, store and
  audit log use only the standard library, which keeps the supply chain to
  the Go toolchain and two base images.
- **CSRF:** `SameSite=Strict` `__Host-` session cookie, an HMAC token in
  `X-CSRF-Token` on every write (including tus chunks), exact `Origin`
  match, `Sec-Fetch-Site` check, no CORS.
- **Isolation between users:** batches and uploads belong to the browser
  session that created them; anything else answers 404.
- **Injection:** client file names never touch the filesystem (files are
  stored by random ID; outbox names keep only characters safe on Linux and
  Windows, see [Outbox format](#outbox-format));
  tus metadata keys are whitelisted; no shell, no SQL; the page uses no
  `innerHTML` and runs under a strict CSP with Trusted Types.
- **Containers:** read-only root filesystem, `cap_drop: ALL` with nothing
  added back, `no-new-privileges`, non-root users, memory, CPU and process
  limits, rotated logs, and internal networks for app↔clamd and proxy↔app.
  clamd runs as the image's `clamav` user through its unprivileged
  entrypoint, reads uploads through group 65532, and mounts only
  `incoming/` and `tmp/`, read-only.
- **Limits:** per-session and per-address caps on work in progress (see
  [Limits](#limits)) and rate limits at the proxy.

## Known limits of stage 1

- No authentication yet: anyone who can reach the page can upload. Restrict
  port 443 to approved client subnets with the host firewall.
- No admin site yet: held files are handled with the commands in
  [Held files](#held-files).
- No audit or quarantine retention pruning yet.
- If a browser declares more files than it ever creates (for example the page
  is closed early), the batch manifest is written once nothing has happened
  in the batch for `UPLOAD_EXPIRY`, with `missing_count` set. Files
  themselves cross as soon as they pass.

## Development

Go 1.27 or later.

```sh
go test -race ./...        # unit tests + end-to-end tests against a fake clamd
go vet ./...
```
