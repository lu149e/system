# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs
RUN cargo build --release --locked && rm -rf src

COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates tzdata \
    && groupadd --system --gid 10001 auth \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin auth \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/auth /app/auth
COPY --from=builder /app/migrations /app/migrations

ENV APP_ADDR=0.0.0.0:8080
EXPOSE 8080

USER 10001:10001

# One-shot migrations: /app/auth migrate (or AUTH_RUN_MODE=migrate).
ENTRYPOINT ["/app/auth"]
