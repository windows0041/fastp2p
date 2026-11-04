FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config python3 libwebsockets-dev libjson-c-dev libssl-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY c/common ./c/common
COPY c/gateway ./c/gateway
RUN cmake -S c/gateway -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build /build --parallel 2 \
    && cmake --install /build --prefix /opt/fastp2p

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libwebsockets17 libjson-c5 libssl3 libsqlite3-0 ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/fastp2p /opt/fastp2p
RUN install -d -o 65532 -g 65532 -m 700 /var/lib/fastp2p
VOLUME ["/var/lib/fastp2p"]
USER 65532:65532
ENV FASTP2P_TLS_CERT=/etc/fastp2p/tls/server.crt \
    FASTP2P_TLS_KEY=/etc/fastp2p/tls/server.key \
    FASTP2P_DATABASE=/var/lib/fastp2p/nodes.sqlite3
EXPOSE 27180-27181/tcp 27183/tcp 27180-27183/udp 10008/tcp
ENTRYPOINT ["/opt/fastp2p/bin/fastp2p-gateway"]
CMD ["--bind", "0.0.0.0", "--apibind", "0.0.0.0"]
