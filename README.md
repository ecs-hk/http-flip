# httpflip

A small HTTP service for uploading and downloading files.

Uploads and deletes require a bearer token. Downloads do not. The split is
deliberate: an upload or delete mutates shared state and so needs an
identity attached to it, whereas a download is a read of a capability URL
whose path is ~282 bits of unguessable secret (a ~94-bit directory plus a
~188-bit file name).

- Maximum upload size: 10 MiB, configurable
- No third-party dependencies; standard library only
- No database; everything is a file on a volume
- Built for OpenShift, but runs anywhere

## API

| Route | Auth | Purpose |
|---|---|---|
| `POST /upload` | bearer token | Store one file part |
| `PUT /upload` | bearer token | Same; every request mints a new path |
| `GET /data/<dir>/<file>` | none | Download |
| `HEAD /data/<dir>/<file>` | none | Size and metadata only |
| `DELETE /data/<dir>/<file>` | bearer token | Delete the object |
| `GET /healthz`, `/livez`, `/readyz` | none | Probes |
| anything else | none | `404` |

A known path called with the wrong method — `GET /upload`, `POST
/data/<dir>/<file>`, `DELETE /healthz` — answers `405` with an
`Allow` header naming the methods that path accepts.

### Upload

```console
$ curl --fail -X POST \
    -H "Authorization: Bearer $HTTPFLIP_TOKEN" \
    -F "file=@report.pdf" \
    https://httpflip.example.com/upload
{
  "path": "/data/XcFCyemkp1GeXYZq/9mZqT4rKxW2vNbHdY7pLcAeFjGhQwErT",
  "filename": "report.pdf",
  "content_type": "application/pdf",
  "size": 1048576,
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "uploaded_by": "uploader-01"
}
```

Send the `path` back to whoever should receive the file. It is a complete URL
path, so it can be `GET` directly.

`201` on success. Otherwise:

| Status | Meaning |
|---|---|
| `400` | Unparseable multipart body, no file part, or more than one |
| `401` | Missing or unrecognised bearer token |
| `403` | Token recognised but expired |
| `405` | A known path used with the wrong method |
| `413` | File exceeds the configured limit (10 MiB by default) |
| `415` | `Content-Type` is not `multipart/*` |
| `500` | Storage failure |

### Download

```console
$ curl --fail -O -J https://httpflip.example.com/data/XcFC.../9mZq...
```

Range requests and `HEAD` both work. Downloads are always sent as
`Content-Type: application/octet-stream` with
`Content-Disposition: attachment`, so a browser saves the file rather than
rendering it. That is what stops an uploaded `.html` or `.svg` from becoming
script execution in a downloader's browser.

### Delete

```console
$ curl --fail -X DELETE \
    -H "Authorization: Bearer $HTTPFLIP_TOKEN" \
    https://httpflip.example.com/data/XcFC.../9mZq...
```

`204` on success with an empty body. Any valid (non-expired) token may
delete any known URL: knowledge of the unguessable path is the capability,
and the service keeps no per-object owner to check against. A second delete
of the same path answers `404`, exactly like a download of a missing object.
Unauthenticated or expired callers get `401` / `403`, the same as uploads.
A storage failure gets `500`, and the object may still be there.
The object, its sidecar and its now-empty parent directory are removed; a
download already holding the file open keeps its bytes.

## Managing bearer tokens

This is the operator's runbook.

### The file format

One credential per line: `name`, `secret`, `expiry`. Blank lines and `#`
comments are ignored, including a trailing comment after the third field.

```
# name         secret                        expiry
uploader-01    9f2c1a3d4e5f60718293a4b5c6d7e8f90   -
uploader-02    a41b7e8829304a1b2c3d4e5f60718293   2027-03-01T00:00:00Z
batch-runner   c3d4e5f60718293a4b5c6d7e8f90a1b2c   -
```

- `name` is how the upload appears in logs. Letters, digits, `.`, `_` and `-`,
  up to 64 characters.
- `secret` is 64 hex characters, i.e. 32 bytes, case-insensitive.
- `expiry` is an RFC 3339 timestamp, or `-` for no expiry.

A malformed line is a startup error, not a skipped line. If you mistype one,
the service refuses to come up rather than quietly serving with fewer
credentials than you believe.

### Minting a token

```console
$ openssl rand -hex 32
3f8a1c9e2b7d4056a1e3f8c2b9d407e5a1c3f8e2b7d4056a1e3f8c2b9d407e5a
```

Prefer a token per client rather than one shared secret. It costs nothing, and
it means logs can answer *who* uploaded something, and revoking one client
does not log out the others.

### Storing tokens as a Secret

Keep the file outside the repository. A template with the right shape is in
`deploy/secret-template.yaml`.

```console
$ oc create secret generic httpflip-auth --from-file=tokens=./tokens
```

The deployment mounts it at `/etc/httpflip/tokens`. The kubelet keeps
projected Secret volumes synchronised, so **editing the Secret updates the file
in a running pod without a restart.**

### Rolling out

```console
$ oc apply -f deploy/pvc.yaml
$ oc apply -f deploy/deployment.yaml -f deploy/service.yaml -f deploy/route.yaml
```

### Rotating a token

Rotation needs no rollout. Adding, removing and expiring all take effect on
the next upload, because the service re-reads the token file on each upload.

1. **Add** the new credential alongside the old one:

   ```console
   $ oc patch secret httpflip-auth --type merge \
       -p "{\"stringData\":{\"tokens\":\"$(cat tokens.new)\"}}"
   ```

   Wait a few seconds for the kubelet to sync the volume.

2. **Move clients over.** Verify the new one works:

   ```console
   $ curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
       -H "Authorization: Bearer $NEW_TOKEN" \
       -F "file=@/etc/hostname" https://httpflip.example.com/upload
   201
   ```

3. **Retire** the old credential by removing its line, and save the Secret
   again. Anyone still using it now gets `401`.

There is no window in which both credentials are refused, because the service
keeps serving the previously loaded set if it cannot parse the new one. It logs
`cannot reload token file` when that happens, so a typo is visible rather than
silent.

### Revoking a token

Remove the line and save the Secret. Effective within a second, no rollout.
Only the named client is affected.

### Expiring a token

Set the third field to a timestamp. Unlike revocation, no further action is
needed: the service evaluates expiry at authentication time, so the credential
stops working on its own and the client receives `403` rather than `401`. That
difference is deliberate — `403` means "you were valid and something changed",
which points at rotation or a clock problem, while `401` means the credential
was never recognised.

### Handing a token to a user

Out of band: a password manager, or `oc` for colleagues. Never put a token in a
URL, since URLs end up in proxy logs, and never in this repository. Tokens
should travel over the Route, which terminates TLS. The in-cluster Service
path is plain HTTP and must not be treated as credential-safe.

### Adding a second credential type

Not needed today. The file format already supports per-token expiry and
per-token names, which is what most operational needs reduce to. HMAC-signed
short-lived tokens would matter only if the clients were services that should
not hold a long-lived secret at all.

## Running locally

```console
$ mkdir -p /tmp/httpflip && cd /tmp/httpflip
$ openssl rand -hex 32 > secret
$ printf 'dev  %s  -\n' "$(cat secret)" > tokens
$ cat tokens

$ go run . -addr :8080 -data-dir ./data -tokens-file ./tokens -log-level debug
```

```console
$ TOKEN=$(cat secret)
$ echo hello > greeting.txt
$ PATH_OUT=$(curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    -F "file=@greeting.txt" http://localhost:8080/upload | jq -r .path)
$ curl -sS "http://localhost:8080$PATH_OUT"
hello
```

## Configuration

| Flag | Default | Notes |
|---|---|---|
| `-addr` | `:8080` | Listen address |
| `-data-dir` | `/data` | Must be writable; checked at startup |
| `-tokens-file` | `/etc/httpflip/tokens` | Checked at startup |
| `-max-upload-bytes` | `10485760` | Maximum size of one file, in bytes. Default 10 MiB |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-shutdown-timeout` | `30s` | Drain window on `SIGTERM` |
| `-version` | | Print version and exit |

The upload limit defaults to 10 MiB. It lives in exactly one place,
`server.DefaultMaxUploadBytes` in `internal/server/server.go`, and the flag
above takes its default from that constant, so there is no second copy to
drift.

Timeouts are fixed in `server.DefaultConfig`: 10s for request headers, 5m for a
whole request, 5m for a response, 120s idle, 64 KiB of headers. The 5-minute
figures are derived from the upload limit, not chosen independently — 10 MiB at
about 35 KB/s arrives just inside 5m, which is a slow-but-real link. Anything
tighter starts failing well-behaved clients. The response timeout matters for
downloads the same way the request timeout matters for uploads.

If you raise `-max-upload-bytes`, check both timeouts against it and raise
`haproxy.router.openshift.io/timeout` on the Route to match, or the router will
cut off a large transfer before the service ever sees it. `-max-upload-bytes`
is additionally capped at 1 TiB so a typo cannot turn the volume into the only
limit.

## Operational notes

**Capacity is the volume's problem, not the service's.** Uploads are
authenticated, so only token holders can consume space, but there is no quota
inside the service. Size the PVC deliberately and monitor it. `DELETE` with a
valid token reclaims a single object; there is no bulk expiry, so plan a
reaping story for abandoned URLs.

**Download URLs are capabilities, not revocable grants.** The path is the
credential. Once a URL has been shared, logged by a proxy, or pasted into
chat, anyone holding it can download it, and anyone holding it plus a valid
bearer token can delete it. `DELETE` withdraws the bytes going forward but
does not undo copies already made. `Cache-Control: no-store` and
`Referrer-Policy: no-referrer` reduce accidental leakage; they do not undo it.

**The network perimeter is the real boundary.** Bearer tokens stop a client
that *can* reach the pod from misusing uploads and deletes. Nothing in the
service stops a client that cannot. Reachability (Route, IP controls) is
managed outside this repository; treat the token as a second layer rather
than the only one.

**Uploaded files are never interpreted.** Every download carries
`X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` and
`Content-Security-Policy: sandbox`, and the `Content-Type` is set explicitly so
the standard library never sniffs the bytes. Client-supplied filenames are
stripped of control characters before they reach a response header, so an
uploader cannot inject headers into somebody else's download.

**`X-Forwarded-For` is logged, never trusted for access control.** It is
trivially spoofable unless the proxy rewrites it. The audit trail wants it; the
security decision does not.

**Logs are structured JSON.** Useful fields: `token` on uploads and rejections,
`path`, `size`, `sha256`, `remote` (the immediate peer, usually the router) and
`client` (the reported caller). Token *names* are logged; token values never
are. Probe traffic is logged at `debug` so it does not bury everything else.

## Development

```console
$ go build ./...
$ go test -race ./...
$ go vet ./...
$ gofmt -l .
```

The test suite covers the parts where a mistake is silent: the path grammar and
a table of traversal attempts, token parsing and rotation, size limits leaving
nothing on disk, filename handling in response headers, and an end-to-end test
that starts the real binary and drains it with `SIGTERM`.

`main_test.go` compiles the binary and starts it, so `go test ./...` needs a
working Go toolchain on `PATH` and a few seconds.

### Layout

```
main.go                     flags, wiring, SIGTERM, graceful drain
internal/store/             naming, path validation, streaming writes, sidecars
internal/auth/              token file parsing, constant-time verify, hot reload
internal/server/            routing, middleware, handlers
deploy/                     OpenShift manifests
```