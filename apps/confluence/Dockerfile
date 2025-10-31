FROM rustlang/rust:nightly-bookworm-slim AS chef
RUN apt-get update && apt-get install -y curl clang libssl-dev lld pkg-config && apt-get install -y --no-install-recommends ca-certificates
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
RUN cargo binstall cargo-chef sccache --no-confirm 
ENV RUSTC_WRAPPER=sccache
WORKDIR /usr/src/app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /usr/src/app/recipe.json recipe.json
RUN --mount=type=cache,mode=0777,target=/home/root/.cache/sccache cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,mode=0777,target=/home/root/.cache/sccache cargo build --release --bin confluence_server
RUN sccache --show-stats

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y openssl && apt-get install -y --no-install-recommends ca-certificates
COPY --from=builder /usr/src/app/target/release/confluence_server /usr/local/bin/confluence_server
CMD ["confluence_server"]
