# Build stage. Pinned to the toolchain in go.mod; pin by digest on release
# (docker inspect --format '{{.RepoDigests}}') so a rebuild is reproducible.
FROM docker.io/library/golang:1.27.4-trixie AS build
# Release builds pass -X main.version=... so -version reports the release
# rather than the fallback.
ARG VERSION=dev
WORKDIR /src
# Dependencies first, so a source-only change reuses the module layer. This
# project has no third-party dependencies, so go.mod alone is enough.
COPY go.mod ./
RUN go mod download
COPY main.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" -o /out/httpflip .

# Runtime stage. Pin by digest on release for the same reason as above.
FROM docker.io/library/debian:trixie-slim

LABEL name="httpflip" \
      description="Authenticated file upload and capability-URL download service"

# debian-slim ships no CA bundle. The service makes no outbound calls today,
# but installing one here keeps a future client from needing a base-image
# change.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 0555 rather than whatever mode the build stage left behind: the binary must
# be readable and executable, never writable, inside the image.
COPY --from=build --chmod=0555 /out/httpflip /usr/local/bin/httpflip
# A non-root default. Under OpenShift the SCC overrides this with a UID from
# the namespace range; the service is built to work with whatever it is given.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/httpflip"]
EXPOSE 8080
