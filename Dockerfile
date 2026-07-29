FROM rust:1.97.1-slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    clang \
    git \
    libclang-dev \
    llvm \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf '%s\n' 'fn main() {}' > src/main.rs
RUN cargo fetch --locked

COPY src ./src
COPY sdk ./sdk

RUN cargo build --release --locked

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zeroserve /usr/local/bin/zeroserve

WORKDIR /srv

EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/zeroserve"]
