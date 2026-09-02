FROM golang:1.27-alpine AS builder

WORKDIR /build

ARG COMMIT_SHA=dev
ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-w -s -X main.buildVersion=${VERSION} -X main.commitHash=$(echo ${COMMIT_SHA} | cut -c1-6)" \
    -o lancert ./cmd/lancert/

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-w -s" \
    -o healthcheck ./cmd/healthcheck/

RUN mkdir /data && chown 65532:65532 /data

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/lancert /usr/local/bin/lancert
COPY --from=builder /build/healthcheck /usr/local/bin/healthcheck
COPY --from=builder --chown=nonroot:nonroot /data /data

VOLUME /data
EXPOSE 53/udp 53/tcp 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["lancert"]
CMD ["-data-dir", "/data", "-http-addr", ":8443"]
