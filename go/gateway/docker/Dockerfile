FROM golang:1.20.14 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openp2p-gateway .

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/log && chown -R 1000:1000 /app
WORKDIR /app
COPY --from=build /out/openp2p-gateway /app/openp2p-gateway
USER 1000:1000
EXPOSE 10008/tcp 27180/tcp 27181/tcp 27183/tcp
EXPOSE 27180/udp 27181/udp 27182/udp 27183/udp
ENTRYPOINT ["/app/openp2p-gateway"]
CMD ["-cert", "/certs/server.crt", "-key", "/certs/server.key"]
