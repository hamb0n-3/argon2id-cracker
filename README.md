# Argon2id Cracker

A high-performance, concurrent Argon2id hash cracker written in Rust, designed for penetration testing, red teaming, and password recovery. This tool can leverage both CPU and GPU (via OpenCL) to accelerate the cracking process.

## Features

- **Multi-Core CPU Cracking:** Utilizes all available CPU cores for maximum performance.
- **GPU Acceleration:** Supports OpenCL for offloading the cracking process to a GPU for significant speed improvements.
- **Wordlist Attacks:** Reads passwords from a wordlist file.
- **Potfile Support:** Saves cracked hashes to a potfile (`potfile.txt` by default) to avoid re-cracking them in future sessions.
- **Session Management:** Can save and resume cracking sessions.
- **Cross-Platform:** Compiles and runs on Linux, macOS, and Windows.

## Prerequisites

- **Rust Toolchain:** Install Rust and Cargo from [rustup.rs](https://rustup.rs/).
- **OpenCL SDK (for GPU mode):**
  - **NVIDIA:** Install the CUDA Toolkit.
  - **AMD:** Install the AMD ROCm SDK.
  - **Intel:** Install the Intel OpenCL SDK.
  Ensure your GPU drivers are up to date.

## Building

A convenience script is provided to build the project.

First, make the script executable:
```bash
chmod +x build.sh
```

Then run it:
```bash
./build.sh
```

Alternatively, you can build it manually using Cargo:
```bash
cargo build --release
```
The compiled binary will be located at `target/release/argon2id-cracker`.

## Usage

```
argon2id-cracker [OPTIONS] --hash <HASH_OR_FILE>
```

### Options

-   `-h, --hash <HASH_OR_FILE>`: The Argon2 hash string or a path to a file containing hashes (one per line).
-   `-w, --wordlist <WORDLIST>`: Path to the wordlist file.
-   `--rules-file <RULES_FILE>`: Path to a custom rules file for mangling passwords.
-   `--mask <MASK>`: Defines a mask for a mask-based attack (e.g., `?d?d?d?l?l`).
-   `--potfile <POTFILE>`: Path to the potfile. [default: `potfile.txt`]
-   `--session <SESSION>`: Session name to save/resume progress.
-   `--gpu`: Enable GPU acceleration.

### Examples

**CPU Cracking with a Wordlist:**
```bash
./target/release/argon2id-cracker --hash '$argon2id$v=19$m=65536,t=3,p=4$SALT$HASH' --wordlist /path/to/rockyou.txt
```

**GPU Cracking with a Wordlist:**
```bash
./target/release/argon2id-cracker --hash /path/to/hashes.txt --wordlist /path/to/rockyou.txt --gpu
``` 