FROM golang:1.26-alpine AS builder

WORKDIR /build

ARG COMMIT_SHA=dev

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-w -s -X main.commitHash=$(echo ${COMMIT_SHA} | cut -c1-7)" \
    -o lancert ./cmd/lancert/

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-w -s" \
    -o healthcheck ./cmd/healthcheck/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/lancert /usr/local/bin/lancert
COPY --from=builder /build/healthcheck /usr/local/bin/healthcheck

VOLUME /data
EXPOSE 53/udp 53/tcp 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["lancert"]
CMD ["-data-dir", "/data", "-http-addr", ":8443"]
