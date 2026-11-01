FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config libwebsockets-dev libjson-c-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . ./
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build /build --parallel 2 \
    && cmake --install /build --prefix /opt/openp2p-c

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libwebsockets17 libjson-c5 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/openp2p-c /opt/openp2p-c
USER 65532:65532
ENV OPENP2P_TLS_CERT=/etc/openp2p/tls/server.crt \
    OPENP2P_TLS_KEY=/etc/openp2p/tls/server.key
EXPOSE 27180-27181/tcp 27183/tcp 27180-27183/udp 10008/tcp
ENTRYPOINT ["/opt/openp2p-c/bin/openp2p-gateway-c"]
CMD ["--bind", "0.0.0.0", "--apibind", "0.0.0.0"]
