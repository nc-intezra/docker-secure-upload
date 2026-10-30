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
                                 └────────────▶ clamd (read-only /data)
                                                      │
          passed / unscanned ──▶ /data/outbox/  ◀─────┘   (atomic rename + .sha256 + batch manifest)
          infected           ──▶ /data/quarantine/ (or deleted when quarantine is off)
          scan error / limit ──▶ /data/quarantine/ (held)
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
| `OK` but file larger than `CLAMD_MAX_SCAN_SIZE` | unscanned (policy `pass`) or held | outbox, flagged in the manifest |
| `Heuristics.Limits.Exceeded.MaxFileSize` / `.MaxScanSize` | unscanned (policy `pass`) or held | outbox, flagged in the manifest |
| `Heuristics.Limits.Exceeded.MaxRecursion` / `.MaxFiles` / `.MaxScanTime` | held | quarantine/ |
| any other `FOUND` (including `Heuristics.Encrypted.*`) | quarantined, or deleted if `QUARANTINE_ENABLED=false` | quarantine/ or removed |
| `ERROR`, timeout, unexpected reply | held | quarantine/ |

The service never scans until clamd has passed an EICAR self-test, which is
repeated hourly. If clamd is unreachable, files wait in the queue instead of
being held.

## Outbox format

```
outbox/
  20261030T141502Z-jsmith-a3f9c1_001_Site_Survey.zip
  20261030T141502Z-jsmith-a3f9c1_001_Site_Survey.zip.sha256   # "<hex>  <name>", works with sha256sum -c
  20261030T141502Z-jsmith-a3f9c1.manifest.json
```

The manifest lists every passed file with its original name, size, SHA-256,
`scan_status` (`clean` or `unscanned`) and signature database. Withheld files
are only counted; their names never cross the diode.

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
/srv/diode-upload/          # DIODE_ROOT, mounted at /data
  outbox/                   # the folder the diode watches (2-second settle time)
  incoming/                 # created by the service
  quarantine/               # created by the service
  tmp/                      # created by the service, emptied at startup
```

```sh
sudo install -d -m 0755 -o 65532 -g 65532 /srv/diode-upload
sudo install -d -m 2775 -o 65532 -g <diode-group> /srv/diode-upload/outbox
```

The app runs as uid 65532. Files are created mode 0644 so clamd and the
diode can read them; the diode needs write access to `outbox/` to remove
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
docker compose exec app diode-upload verify-audit      # check the audit hash chain
```

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `no configuration file provided: not found` | The Docker snap is in use. See [Prerequisites](#prerequisites). |
| `state store: mkdir /state/batches: permission denied` | The `state` volume was created by an image from before v0.5.1, so it is owned by root. If nothing has been uploaded yet: `docker compose down`, then `docker volume rm diode-upload_state`, then `docker compose up -d --build`. To keep existing data instead: `docker run --rm -v diode-upload_state:/state busybox chown -R 65532:65532 /state` |
| `storage layout: ... permission denied` or `outbox: ... no such file or directory` | `DIODE_ROOT` or its `outbox/` is missing or not writable by uid 65532. See [Host layout](#host-layout). |
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
| `UPLOAD_EXPIRY` | `24h` | Unfinished uploads are removed after this |
| `CLAMD_ADDR` | `clamd:3310` | |
| `CLAMD_PATH_PREFIX` | `$DATA_DIR` | Where clamd sees `DATA_DIR` (for an external clamd) |
| `CLAMD_MAX_SCAN_SIZE` | `4000M` | Must match `MaxScanSize` in `clamd.conf` |
| `SCAN_CONCURRENCY` / `SCAN_TIMEOUT` | `2` / `2h` | |
| `OVERSIZE_POLICY` | `pass` | `pass`, `hold` or `reject` (refused at upload) |
| `QUARANTINE_ENABLED` | `true` | `false` deletes infected files instead |
| `MAX_BATCH_FILES` | `500` | |
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
  stored by random ID; outbox names are sanitized to `[A-Za-z0-9._-]`);
  tus metadata keys are whitelisted; no shell, no SQL; the page uses no
  `innerHTML` and runs under a strict CSP with Trusted Types.
- **Containers:** non-root, read-only root filesystem, `cap_drop: ALL`
  (except clamd, whose image needs to drop privileges itself),
  `no-new-privileges`, internal networks for app↔clamd and proxy↔app.

## Known limits of stage 1

- No rate limiting in the app yet; nginx applies a coarse per-IP limit.
- No admin site yet: quarantined and held files can only be handled on the
  host (`/data/quarantine/<id>`, details in `/state/uploads/<id>.json`).
- No audit or quarantine retention pruning yet.
- If a browser declares more files than it ever creates (for example the page
  is closed early), the batch manifest is written once the batch is 24 hours
  old, with `missing_count` set. Files themselves cross as soon as they pass.

## Development

```sh
go test -race ./...        # unit tests + end-to-end tests against a fake clamd
go vet ./...
```
