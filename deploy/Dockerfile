# syntax=docker/dockerfile:1.7
# Multi-stage build: dashboard (Node), binaries (Rust), then a small non-root runtime image.

FROM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1.99-bookworm AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p customs -p customs-scan \
 && strip target/release/customs target/release/customs-scan

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/customs customs \
 && mkdir -p /var/lib/customs && chown customs /var/lib/customs
COPY --from=rust /src/target/release/customs /src/target/release/customs-scan /usr/local/bin/
COPY --from=web /src/web/dist /usr/share/customs/ui
COPY models /usr/share/customs/models
USER customs
ENV CUSTOMS_BIND=0.0.0.0:7878 \
    CUSTOMS_DATA_DIR=/var/lib/customs \
    CUSTOMS_MODELS=/usr/share/customs/models
EXPOSE 7878
VOLUME ["/var/lib/customs"]
ENTRYPOINT ["customs", "serve", "--ui-dir", "/usr/share/customs/ui"]
