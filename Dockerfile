# syntax=docker/dockerfile:1.4
ARG LLVM_VERSION=20
ARG RELEASE_MODE=""

FROM --platform=$BUILDPLATFORM rust:bookworm AS build

ARG TARGETARCH
ARG RELEASE_MODE="debug"

WORKDIR /buildroot

RUN dpkg --add-architecture ${TARGETARCH} && \
    apt-get update && \
    apt-get install -y "musl-tools:$TARGETARCH" "crossbuild-essential-$TARGETARCH"

RUN if [ "$TARGETARCH" = "amd64" ] ; then export TOOLCHAIN="x86_64-unknown-linux-musl"; fi; \
    if [ "$TARGETARCH" = "arm64" ] ; then export TOOLCHAIN="aarch64-unknown-linux-musl"; fi; \
    rustup target add "$TOOLCHAIN"

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# ring requires those variables for cross-compilation
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clink-self-contained=yes -Clinker=rust-lld"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clink-self-contained=yes -Clinker=rust-lld"

RUN if [ "$RELEASE_MODE" = "debug" ] ; then export BUILD_FLAG=""; fi; \
    if [ "$RELEASE_MODE" = "release" ] ; then export BUILD_FLAG="--release"; fi; \
    if [ "$TARGETARCH" = "amd64" ] ; then export TOOLCHAIN="x86_64-unknown-linux-musl"; fi; \
    if [ "$TARGETARCH" = "arm64" ] ; then export TOOLCHAIN="aarch64-unknown-linux-musl"; fi; \
    cargo build --target=$TOOLCHAIN $BUILD_FLAG; \
    mv "target/$TOOLCHAIN/$RELEASE_MODE/origin" target/origin

FROM --platform=$TARGETPLATFORM scratch AS final
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /buildroot/target/origin /origin
EXPOSE 8000
ENTRYPOINT ["/origin"]
