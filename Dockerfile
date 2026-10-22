# syntax=docker/dockerfile:1

# Build on the runner's own platform and cross-compile, so multi-arch images
# don't need CPU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/tabs ./cmd/tabs \
 && mkdir -m 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/tabs /tabs
# The database lives here. A new named volume inherits this ownership, so
# the nonroot user (65532) can write to it.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME /data
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/tabs", "healthcheck"]
ENTRYPOINT ["/tabs"]
