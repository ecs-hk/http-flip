# Build stage.
FROM docker.io/library/golang:1.24 AS build
WORKDIR /src
# Dependencies first, so a source-only change reuses the module layer. This
# project has no third-party dependencies, so go.mod alone is enough.
COPY go.mod ./
COPY main.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/httpflip .

# Runtime stage.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/httpflip /usr/local/bin/httpflip
# A non-root default. Under OpenShift the SCC overrides this with a UID from
# the namespace range; the service is built to work with whatever it is given.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/httpflip"]
