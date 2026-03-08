FROM node:20-bookworm-slim

WORKDIR /app

COPY webapp/package*.json ./
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ cmake pkg-config libssl-dev libsodium-dev nlohmann-json3-dev \
 && npm install --omit=dev \
 && rm -rf /var/lib/apt/lists/*

COPY webapp/src ./src
COPY webapp/public ./public
COPY webapp/data ./data
COPY security_core ./security_core
RUN cmake -S /app/security_core -B /app/security_core/build \
 && cmake --build /app/security_core/build --config Release

RUN mkdir -p /app/logs /app/uploads

EXPOSE 3000
CMD ["npm", "start"]
