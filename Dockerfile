# Build the manager binary
# Override BASE_IMAGE to build from another registry, e.g. docker.io/library/golang:1.26
ARG BASE_IMAGE=golang:1.26
# The compiler always runs on the platform of the machine that builds the image and
# cross-compiles for the target platform. Building for linux/arm64 on an amd64 machine, or the
# other way around, therefore needs no emulation, and is as fast as building for the host.
FROM --platform=${BUILDPLATFORM} ${BASE_IMAGE} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build for the platform that the image is made for. GOARCH has no default so that a build
# without --platform, which has TARGETARCH set to the architecture of the host, still works.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o manager ./cmd

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/LICENSE /licenses/LICENSE
USER 65532:65532

ENTRYPOINT ["/manager"]
