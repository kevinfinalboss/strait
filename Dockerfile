# syntax=docker/dockerfile:1

FROM rust:1.99-slim-trixie AS build
WORKDIR /src

# Build dependencies in their own layer, so editing the code does not rebuild them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked --bin strait \
    && rm -rf src

COPY src src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked --bin strait

# Distroless: no shell or package manager, runs as an unprivileged user.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/strait /usr/local/bin/strait
# Numeric so Kubernetes can verify runAsNonRoot; 65532 is distroless' nonroot user.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/strait"]
