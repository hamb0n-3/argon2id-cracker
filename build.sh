#!/bin/bash

set -e

# --- Configuration ---
BINARY_NAME="argon2id-cracker"
DOCKER_IMAGE_NAME="argon2id-cracker-static-builder"
DEFAULT_TARGET_DIR="./target/release"
STATIC_TARGET_DIR="./target/static"
STATIC_BINARY_PATH="${STATIC_TARGET_DIR}/${BINARY_NAME}"

# --- Helper Functions ---
print_usage() {
    echo "Usage: $0 [--clean] [--static]"
    echo
    echo "Options:"
    echo "  --clean     Remove the build artifact directory (target/)."
    echo "  --static    Build a statically linked binary using Docker."
    echo "  (no args)   Run a standard release build (cargo build --release)."
}

# --- Argument Parsing ---
if [ "$1" == "--clean" ]; then
    echo "Cleaning project..."
    cargo clean
    echo "Project cleaned."
    exit 0
fi

if [ "$1" == "--static" ]; then
    echo "Building statically linked binary with Docker..."
    
    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null || ! docker info &> /dev/null; then
        echo "Error: Docker is not installed or not running. Please start Docker and try again."
        exit 1
    fi
    
    # Build the Docker image
    docker build --no-cache -t "${DOCKER_IMAGE_NAME}" .
    
    # Create the target directory for the static binary
    mkdir -p "${STATIC_TARGET_DIR}"

    # Create a container from the image to extract the binary
    echo "Extracting binary from Docker image..."
    container_id=$(docker create "${DOCKER_IMAGE_NAME}")
    
    # Docker cp requires the destination directory to exist.
    docker cp "${container_id}:/argon2id-cracker" "${STATIC_BINARY_PATH}"
    
    # Clean up the container
    docker rm "${container_id}"
    
    echo "Static build successful!"
    echo "You can find the binary at: ${STATIC_BINARY_PATH}"
    file "${STATIC_BINARY_PATH}" # Show file type to confirm it's static
    exit 0
fi

if [ "$#" -ne 0 ]; then
    echo "Error: Invalid argument '$1'."
    print_usage
    exit 1
fi

# --- Default Build ---
echo "Building Argon2id Cracker in release mode..."
RUSTFLAGS="-L${PWD}/lib" cargo build --release

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "You can find the binary at: ${DEFAULT_TARGET_DIR}/${BINARY_NAME}"
else
    echo "Build failed. Please check for errors."
fi 