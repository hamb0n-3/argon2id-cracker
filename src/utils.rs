//! # Utilities
//!
//! This module provides utility structs and functions for handling persistent state,
//! specifically for the potfile and session management.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Manages the potfile, which stores successfully cracked hashes and their passwords.
///
/// The potfile has two main purposes:
/// 1. To avoid re-cracking hashes that have already been solved in previous sessions.
/// 2. To serve as the final record of successfully cracked credentials.
/// It uses a `HashSet` for efficient, in-memory lookups of already cracked hashes.
pub struct Potfile {
    path: String,
    cracked_hashes: HashSet<String>,
}

impl Potfile {
    /// Creates a new `Potfile` instance and loads any existing entries from disk.
    /// The file format is `hash:password`, one per line.
    ///
    /// # Arguments
    /// * `path` - The path to the potfile.
    pub fn new(path: &str) -> io::Result<Self> {
        let mut cracked_hashes = HashSet::new();
        let path_obj = Path::new(path);

        if path_obj.exists() {
            let file = File::open(path_obj)?;
            let reader = io::BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                // The potfile format is hash:password. We only need the hash for lookups.
                if let Some(hash) = line.split(':').next() {
                    cracked_hashes.insert(hash.to_string());
                }
            }
        }

        Ok(Self {
            path: path.to_string(),
            cracked_hashes,
        })
    }

    /// Checks if a hash is already present in the potfile.
    ///
    /// # Arguments
    /// * `hash_str` - The full hash string to check.
    pub fn contains(&self, hash_str: &str) -> bool {
        self.cracked_hashes.contains(hash_str)
    }

    /// Appends a newly cracked hash and password to the potfile on disk and
    /// adds the hash to the in-memory set.
    ///
    /// # Arguments
    /// * `hash_str` - The hash that was cracked.
    /// * `password` - The found password.
    pub fn add(&mut self, hash_str: &str, password: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{}:{}", hash_str, password)?;

        // Also add to our in-memory set to avoid re-cracking in the same session.
        self.cracked_hashes.insert(hash_str.to_string());

        Ok(())
    }
}

// --- Session Management ---

/// Represents the state of a cracking session to allow for resuming.
///
/// This struct is serialized to and from a JSON file (`.session`). It stores
/// the progress of a given attack type so the user can stop and later resume
/// without losing work.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Session {
    /// The last line number processed from the wordlist (for wordlist attacks).
    pub wordlist_offset: u64,
    /// The state of the mask iterator (for mask attacks).
    pub mask_indices: Option<Vec<usize>>,
    /// The attack mode ("wordlist" or "mask") this session corresponds to.
    /// Used to prevent resuming a session with the wrong attack type.
    pub attack_mode: String,
}

impl Session {
    /// Loads a session from a file. If the file doesn't exist, it returns a
    /// new, default `Session` instance, indicating a new session should start.
    pub fn load(session_name: &str) -> io::Result<Self> {
        let path = format!("{}.session", session_name);
        if !Path::new(&path).exists() {
            return Ok(Session::default());
        }
        let file = File::open(path)?;
        serde_json::from_reader(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Saves the current session state to a JSON file.
    pub fn save(&self, session_name: &str) -> io::Result<()> {
        let path = format!("{}.session", session_name);
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
} 