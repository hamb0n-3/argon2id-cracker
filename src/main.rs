//!
//! # Argon2 Cracker
//!
//! A high-performance, multi-featured Argon2 hash cracker.
//!
//! This crate provides a command-line tool for cracking Argon2 hashes using various
//! attack methods, including wordlist, rule-based, and mask attacks. It supports
//! both CPU and GPU (via OpenCL) for hash verification, along with multi-hash
//! cracking, potfile support for storing cracked hashes, and session resumption.

// Declare the modules we'll be using.
// Each of these corresponds to a .rs file in the src/ directory.

/// Handles command-line argument parsing and validation.
pub mod cli;

/// Contains the main cracking logic, orchestrating the different components.
pub mod cracker;

/// Implements GPU-accelerated hash verification using OpenCL.
pub mod gpu;

/// Provides utility functions for potfile and session management.
pub mod utils;

/// Manages password candidate generation from wordlists, rules, and masks.
pub mod wordlist;

use cli::parse_args;
use std::process;

/// Main entry point of the application.
fn main() {
    // 1. Parse Command-Line Arguments
    // The `cli` module handles everything related to parsing and validating
    // the command-line arguments provided by the user.
    let args = parse_args();

    // 2. Run the Cracker
    // The core logic resides in the `cracker` module. We pass the parsed arguments
    // to it and handle any fatal errors that might occur during its execution.
    if let Err(e) = cracker::run(args) {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}
