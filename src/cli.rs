//! # Command-Line Interface
//!
//! This module defines the command-line arguments for the application using the `clap` crate.
//! It specifies all the options and flags that the user can provide to control the
//! cracking session.

use clap::Parser;

/// A high-performance, concurrent Argon2id hash cracker for red teaming, pentesting, and password recovery.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The Argon2 hash to crack or a path to a file containing multiple hashes (one per line).
    #[arg(short, long)]
    pub hash: String,

    /// Path to the wordlist file. This is mutually exclusive with the --mask option.
    #[arg(short, long)]
    pub wordlist: Option<String>,

    /// Path to a custom rules file. Each line represents a password mangling rule.
    /// This can only be used with a wordlist.
    #[arg(long)]
    pub rules_file: Option<String>,

    /// Defines a mask for a mask-based attack (e.g., "?d?d?d?l?l").
    /// Supported placeholders: ?l (lowercase), ?u (uppercase), ?d (digit), ?s (special).
    /// This is mutually exclusive with the --wordlist option.
    #[arg(long)]
    pub mask: Option<String>,

    /// Path to the potfile. Cracked hashes and their corresponding passwords will be
    /// stored here to avoid re-cracking them in future sessions.
    #[arg(long, default_value = "potfile.txt")]
    pub potfile: String,

    /// Session name to use for saving and resuming progress. A file named '<name>.session'
    /// will be created to store the state.
    #[arg(long)]
    pub session: Option<String>,

    /// Enable GPU acceleration. Requires a compatible OpenCL 2.0+ device and runtime.
    #[arg(long)]
    pub gpu: bool,
}

/// Parses the command-line arguments from the environment.
///
/// # Returns
/// An `Args` struct populated with the user-provided values.
pub fn parse_args() -> Args {
    Args::parse()
} 