FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake g++ make pkg-config libssl-dev libsodium-dev nlohmann-json3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cmake -S . -B build && cmake --build build --config Release

CMD ["/bin/sh", "-c", "./build/security_core --help || sleep infinity"]
