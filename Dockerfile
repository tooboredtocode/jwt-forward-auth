FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /jwt-forward-auth

FROM chef AS planner
# prepare dependencies for caching
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# build project dependencies
COPY --from=planner /jwt-forward-auth/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
# build project
COPY . .
RUN cargo build --release --bin jwt-forward-auth

FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder /jwt-forward-auth/target/release/jwt-forward-auth /jwt-forward-auth
ENV JWT_FWA_PLAIN_LOG=true
ENTRYPOINT ["./jwt-forward-auth"]
