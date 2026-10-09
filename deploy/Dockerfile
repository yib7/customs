# syntax=docker/dockerfile:1.7
# Multi-stage build: dashboard (Node), binaries (Rust), then a small non-root runtime image.

FROM node:24-trixie-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1.99-trixie AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p customs -p customs-scan \
 && strip target/release/customs target/release/customs-scan
# License notices of the crates compiled into the binaries.
ARG CARGO_ABOUT=0.9.2
COPY deploy/about.toml deploy/about.hbs ./deploy/
RUN t="cargo-about-${CARGO_ABOUT}-$(uname -m)-unknown-linux-musl" \
 && url="https://github.com/EmbarkStudios/cargo-about/releases/download/${CARGO_ABOUT}/${t}.tar.gz" \
 && curl -fsSL -o /tmp/ca.tar.gz "$url" \
 && echo "$(curl -fsSL "${url}.sha256" | cut -d' ' -f1)  /tmp/ca.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/ca.tar.gz -C /tmp \
 && "/tmp/${t}/cargo-about" generate --locked -c deploy/about.toml -m crates/customs/Cargo.toml \
      deploy/about.hbs -o THIRD_PARTY_LICENSES.md

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/customs customs \
 && mkdir -p /var/lib/customs && chown customs /var/lib/customs
COPY --from=rust /src/target/release/customs /src/target/release/customs-scan /usr/local/bin/
COPY --from=web /src/web/dist /usr/share/customs/ui
COPY models /usr/share/customs/models
COPY LICENSE /usr/share/doc/customs/
COPY --from=rust /src/THIRD_PARTY_LICENSES.md /usr/share/doc/customs/
USER customs
ENV CUSTOMS_BIND=0.0.0.0:7878 \
    CUSTOMS_DATA_DIR=/var/lib/customs \
    CUSTOMS_MODELS=/usr/share/customs/models
EXPOSE 7878
VOLUME ["/var/lib/customs"]
ENTRYPOINT ["customs", "serve", "--ui-dir", "/usr/share/customs/ui"]
