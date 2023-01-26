FROM --platform=$BUILDPLATFORM golang:1.19 AS builder

ENV PORT=8080
ENV CGO_ENABLED=0
ENV GOPROXY=https://proxy.golang.org,direct

WORKDIR /go/src/app
COPY . .

RUN go build \
  -a \
  -trimpath \
  -ldflags "-s -w -extldflags='-static'" \
  -o /go/bin/server \
  ./cmd/github-token-minter

RUN strip -s /go/bin/server

RUN echo "nobody:*:65534:65534:nobody:/:/bin/false" > /tmp/etc-passwd
RUN chmod -R 555 /go/src/app/configs

# Use a scratch image to host our binary.
FROM scratch
COPY --from=builder /tmp/etc-passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/bin/server /server
COPY --from=builder /go/src/app/configs /configs
COPY --from=builder /go/src/app/lumberjack_config.yml /etc/lumberjack/config.yaml

USER nobody

ENV CONFIGS_DIR=/configs

EXPOSE 8080
ENTRYPOINT ["/server"]
