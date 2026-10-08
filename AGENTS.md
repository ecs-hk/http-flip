# AGENTS.md

Guidance for working in this repository.

## What this is

A single-purpose HTTP service: authenticated file upload, capability-URL
download. Standard library only, no third-party dependencies, no database.
Read `README.md` first; it explains the API and the operational runbook.

## Commands

```bash
go build ./...
go test -race ./...          # includes an end-to-end test of the real binary
go vet ./...
gofmt -l .
```

`main_test.go` builds the binary and starts it, so tests need a working Go
toolchain on `PATH` and take a few seconds. If `golangci-lint` is available,
run it too.

## Architecture

```
main.go                flags/env, wiring, SIGTERM, graceful drain
internal/store/        naming, path validation, streaming writes, sidecars
internal/auth/         token file parsing, constant-time verify, hot reload
internal/server/       routing, middleware, handlers
```

`store.Rel` (`/data`) is the single source of truth for both the download route
pattern and the stored object's URL. Change it in one place.

## Invariants

Do not weaken these without understanding why each exists. They are the
reason the service is safe, and several are enforced by tests that will fail
loudly.

1. **Paths are generated, never derived from input.** Object paths are two
   segments of base58 that this service minted itself. The original filename
   goes in a sidecar, never on disk in a path.

2. **Download paths are validated against a strict grammar.**
   `validatePath` in `internal/store/naming.go` anchors with `\A...\z`, not
   `^...$`, because Go's regexp treats `$` as also matching before a trailing
   newline. The character class contains no `.`, `/` or NUL, so a matching
   segment cannot express a traversal. Do not add `.` to the class.

3. **Malformed and absent paths both answer `404`.** Do not distinguish them;
   the distinction is an existence oracle.

3a. **The upload limit has exactly one definition.**
   `server.DefaultMaxUploadBytes` in `internal/server/server.go` is the only
   place the default exists. `-max-upload-bytes` takes its default from that
   constant, and the body cap and the streaming limit both derive from it at
   runtime. Do not add a second literal, in a test fixture or a manifest
   comment. When changing it, the body timeouts in `DefaultConfig` and the
   Route's `haproxy.router.openshift.io/timeout` annotation are the two things
   that may need to move with it.

4. **Size limits have two layers.** `http.MaxBytesReader` bounds the request
   body; `io.Copy` over `io.LimitReader` bounds the file. Neither alone is
   correct — multipart framing means a body cap set exactly at the limit
   rejects a legitimate payload. The +64 KiB slack covers framing only.

5. **A rejected upload leaves nothing on disk.** The oversized-upload test
   asserts the store directory is empty afterwards. `discard` must remove the
   temp file before the directory, since a directory cannot be removed while
   non-empty.

6. **Permissions are pinned with `chmod`, not left to `Mkdir`/`OpenFile`.**
   Both mask through the process umask. `fs.FileMode` spells setgid as
   `ModeSetgid`, not as POSIX `0o2000`; getting that wrong silently produces a
   plain `0770` and breaks the OpenShift random-UID story.

7. **Auth fails closed.** No token file, no credentials or a malformed one at
   startup means the process refuses to start. There must never be a path where
   "no credentials configured" means "allow everything". A *reload* failure
   keeps the last good set and logs loudly, which is a different and
   deliberate trade.

8. **Token comparison does not early-exit.** `Authenticate` compares against
   every credential and ORs the results. Returning on the first match leaks the
   length of a matching prefix through timing.

9. **Client-supplied filenames are sanitised before reaching a header.**
   `contentDisposition` strips control characters, CR and LF included. Leaving
   them in would let an uploader inject headers into a third party's download.

10. **Download responses never let the browser interpret the content.**
    `Content-Type` is set explicitly, which also stops `http.ServeContent`
    sniffing, and `nosniff`, `attachment` and `CSP: sandbox` follow.

11. **`X-Forwarded-For` is for logs only.** Never for an access decision. The
    network perimeter is what bounds reachability.

## Style

- Comments explain *why*, especially where the obvious approach is a bug.
  The three non-obvious findings above (setgid encoding, umask masking, the
  oversized-upload leak) each cost a bug; do not strip the reasoning.
- No comments that restate the code.
- Prefer stdlib. Adding a dependency needs a good reason.
- Match the existing error handling: sentinel errors plus `%w` wrapping, and
  a JSON error body for anything a client sees.