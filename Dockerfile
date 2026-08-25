FROM rust:1.87-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies: copy manifests + dummy src so cargo resolves all deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo 'pub mod config; pub mod db; pub mod queue; pub mod models; pub mod masscan; pub mod probe; pub mod fingerprint; pub mod enrich; pub mod query; pub mod serve;' > src/lib.rs
RUN mkdir -p src/probe src/enrich src/serve
RUN touch src/probe/mod.rs src/enrich/mod.rs src/serve/mod.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy real source and rebuild (only recompiles our code, deps are cached)
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates masscan libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/scanerr /usr/local/bin/
COPY --from=builder /app/templates /app/templates

WORKDIR /app
ENTRYPOINT ["scanerr"]
CMD ["all"]
