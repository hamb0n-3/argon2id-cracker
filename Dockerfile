# --- Stage 1: Build Stage ---
# Use the official Rust image as a base
FROM rust:1-bullseye as builder

# Install the MUSL target and tools needed for static linking
RUN apt-get update && apt-get install -y musl-tools ocl-icd-opencl-dev
RUN rustup target add x86_64-unknown-linux-musl

# Set the working directory
WORKDIR /app

# Copy the source code first
COPY src ./src
COPY Cargo.toml .
COPY Cargo.lock .
COPY lib/libOpenCL.so /usr/lib/x86_64-linux-gnu/libOpenCL.so.1.0.0
RUN ln -s /usr/lib/x86_64-linux-gnu/libOpenCL.so.1.0.0 /usr/lib/x86_64-linux-gnu/libOpenCL.so.1 && \
    ln -s /usr/lib/x86_64-linux-gnu/libOpenCL.so.1 /usr/lib/x86_64-linux-gnu/libOpenCL.so


# Build the project
RUN cargo build --release --target x86_64-unknown-linux-musl

# --- Stage 2: Final Stage ---
# Use a minimal image to copy the final binary into
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/argon2id-cracker /argon2id-cracker
ENTRYPOINT ["/argon2id-cracker"] 