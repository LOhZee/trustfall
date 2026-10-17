# syntax=docker/dockerfile:1.7
FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/trustfall ./cmd/trustfall

FROM debian:bookworm-20261005-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="TrustFall" \
      org.opencontainers.image.description="GitHub Actions runtime trust-boundary assessment" \
      org.opencontainers.image.source="https://github.com/LOhZee/trustfall" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/trustfall /usr/local/bin/trustfall
# The pinned base predates Debian's perl-base security update. Install the exact
# fixed package version; a superseded/removed version fails the build and forces
# a reviewed Dockerfile update instead of silently accepting a mutable upgrade.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends perl-base=5.36.0-7+deb12u4 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --uid 1001 --user-group --shell /usr/sbin/nologin trustfall \
    && mkdir -p /work \
    && chown trustfall:trustfall /work
USER 1001:1001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/trustfall"]
CMD ["assess", "--profile", "baseline", "--no-network"]
