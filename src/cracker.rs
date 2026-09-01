//! # Cracker Orchestration
//!
//! This is the main engine of the application. It orchestrates the entire cracking
//! process based on the user's command-line arguments.

use crate::cli::Args;
use crate::gpu::GpuVerifier;
use crate::utils::{Potfile, Session}; // Import Session
use crate::wordlist;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use crossbeam_channel::{self};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::error::Error;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Represents a hash to be cracked, containing both the original string and the
/// parsed `PasswordHash` object. The `'static` lifetime is a safe simplification
/// because these hashes live for the entire duration of the program.
#[derive(Clone)]
pub struct TargetHash {
    pub hash_string: String,
    pub parsed_hash: Arc<PasswordHash<'static>>,
}

/// A trait for verifying passwords. This abstracts the verification logic, allowing
/// the application to seamlessly switch between CPU and GPU implementations.
pub trait Verifier: Send + Sync {
    /// Verifies a single password candidate. For batch-based verifiers (like GPU),
    /// this may buffer the candidate internally until a full batch is ready.
    fn verify(&self, candidate: &str);
    
    /// Flushes any buffered candidates to ensure all are processed.
    /// This is a no-op for non-batching verifiers.
    fn flush(&self);
}

/// A `Verifier` implementation that uses the CPU for hash verification.
struct CpuVerifier {
    targets: Arc<Vec<TargetHash>>,
    potfile: Arc<Mutex<Potfile>>,
}

impl Verifier for CpuVerifier {
    fn verify(&self, candidate: &str) {
        let argon2 = Argon2::default();
        for target in self.targets.iter() {
            if argon2.verify_password(candidate.as_bytes(), &target.parsed_hash).is_ok() {
                let mut potfile_lock = self.potfile.lock().unwrap();
                if !potfile_lock.contains(&target.hash_string) {
                    println!("\n✅ Success! Found: {}:{}", target.hash_string, candidate);
                    potfile_lock.add(&target.hash_string, candidate).expect("Failed to write to potfile");
                }
            }
        }
    }
    
    fn flush(&self) {
        // No-op for CPU verifier as it doesn't buffer.
    }
}


/// The main entry point for the cracking logic.
///
/// This function executes the following steps:
/// 1.  Validates command-line arguments to ensure modes are not misused.
/// 2.  Initializes and loads session state if a session name is provided.
/// 3.  Loads target hashes from the specified file or string, filtering out any
///     hashes that are already present in the potfile.
/// 4.  Selects and initializes the appropriate verifier (CPU or GPU).
/// 5.  Spawns a producer thread (either wordlist, rules, or mask-based) to
///     generate password candidates.
/// 6.  If in a session, spawns a thread to periodically save progress.
/// 7.  Starts a pool of consumer threads (via Rayon) that receive candidates,
///     process them in batches using the selected verifier, and update the UI.
/// 8.  Saves the final session state upon completion.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // --- Argument Validation ---
    if args.mask.is_some() && (args.wordlist.is_some() || args.rules_file.is_some()) {
        return Err("Mask attack mode cannot be used with a wordlist or rules file.".into());
    }
    if args.mask.is_none() && args.wordlist.is_none() {
        return Err("You must specify either a wordlist (-w) or a mask (--mask).".into());
    }

    // --- Session Management ---
    let session_arc = if let Some(session_name) = &args.session {
        let session = Session::load(session_name)?;
        let attack_mode = if args.mask.is_some() { "mask" } else { "wordlist" };

        if !session.attack_mode.is_empty() && session.attack_mode != attack_mode {
            return Err(format!(
                "Session '{}' is for a '{}' attack, but the current configuration is for a '{}' attack.",
                session_name, session.attack_mode, attack_mode
            ).into());
        }
        
        println!("✓ Resuming session '{}'.", session_name);
        Arc::new(Mutex::new(session))
    } else {
        // No session, create a default, empty one that won't be saved.
        Arc::new(Mutex::new(Session::default()))
    };


    // 1. Load Hashes
    let potfile = Potfile::new(&args.potfile)?;
    let raw_hashes = load_hashes(&args.hash)?;
    
    let initial_count = raw_hashes.len();
    let targets: Vec<TargetHash> = raw_hashes
        .into_iter()
        .filter(|h| !potfile.contains(h))
        .filter_map(|h_str| {
            let leaked_str: &'static str = Box::leak(h_str.into_boxed_str());
            PasswordHash::new(leaked_str).ok().map(|ph| TargetHash {
                hash_string: leaked_str.to_string(),
                parsed_hash: Arc::new(ph),
            })
        })
        .collect();
    
    let loaded_count = targets.len();
    println!(
        "✓ Loaded {} hashes ({} were already cracked).",
        loaded_count,
        initial_count - loaded_count
    );

    if targets.is_empty() {
        println!("✨ All hashes are already cracked. Nothing to do.");
        return Ok(());
    }
    
    let targets_arc = Arc::new(targets);
    let potfile_mutex = Arc::new(Mutex::new(potfile));

    // 2. Load rules if a file is provided
    let rules = if let Some(rules_path) = &args.rules_file {
        println!("⏳ Loading rules from '{}'...", rules_path);
        let loaded_rules = wordlist::load_rules(rules_path)?;
        println!("✓ {} rules loaded successfully.", loaded_rules.len());
        Some(loaded_rules)
    } else {
        None
    };
    
    // 3. Create Verifier
    let verifier: Arc<dyn Verifier> = if args.gpu {
        println!("Attempting to use GPU acceleration...");
        match GpuVerifier::new(targets_arc.clone(), potfile_mutex.clone()) {
            Ok(gpu_verifier) => Arc::new(gpu_verifier),
            Err(e) => return Err(format!("Failed to initialize GPU verifier: {}. Make sure you have a compatible OpenCL runtime and the argon2_kernel.cl file.", e).into()),
        }
    } else {
        Arc::new(CpuVerifier {
            targets: targets_arc.clone(),
            potfile: potfile_mutex.clone(),
        })
    };

    // 4. Setup Producer-Consumer Channel
    let (sender, receiver) = crossbeam_channel::unbounded();

    // 5. Spawn Producer
    let producer_session_arc = session_arc.clone();
    if let Some(mask) = args.mask.clone() {
        println!("⏳ Starting mask producer for mask '{}'...", mask);
        let mut session_lock = producer_session_arc.lock().unwrap();
        session_lock.attack_mode = "mask".to_string();
        // Unlock before spawning thread
        drop(session_lock);
        wordlist::spawn_mask_producer(mask, producer_session_arc, sender);
    } else if let Some(wordlist_path) = args.wordlist.clone() {
        println!("⏳ Starting wordlist producer...");
        let mut session_lock = producer_session_arc.lock().unwrap();
        session_lock.attack_mode = "wordlist".to_string();
        // Unlock before spawning thread
        drop(session_lock);
        wordlist::spawn_producer(wordlist_path, rules, producer_session_arc, sender);
    }
    // The validation logic at the beginning of the function ensures one of them is Some.
    
    // --- Session Saving Thread ---
    if let Some(session_name) = &args.session {
        let session_save_arc = session_arc.clone();
        let session_name_clone = session_name.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(30));
                let session_to_save = session_save_arc.lock().unwrap();
                if let Err(e) = session_to_save.save(&session_name_clone) {
                    eprintln!("Warning: Failed to save session: {}", e);
                }
            }
        });
    }

    // 6. Setup and Run Consumers
    println!("🔥 Starting concurrent cracking process...");
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {per_sec} - Cracking...")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    receiver
        .into_iter()
        .par_bridge()
        .for_each(|candidate| {
            pb.inc(1);
            verifier.verify(&candidate);
        });
        
    // Flush any remaining candidates in the verifier's buffer (mainly for GPU)
    verifier.flush();

    pb.finish_and_clear();
    
    // Final session save
    if let Some(session_name) = &args.session {
        println!("⏳ Saving final session state...");
        let session_to_save = session_arc.lock().unwrap();
        session_to_save.save(session_name)?;
        println!("✓ Session saved.");
    }

    println!("\nCracking process finished.");
    Ok(())
}

/// Loads hashes from a file (one per line) or treats the input as a single hash string.
///
/// # Arguments
/// * `hash_source` - A path to a file or a single hash string.
///
/// # Returns
/// A `Vec<String>` containing the hashes to be cracked.
fn load_hashes(hash_source: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let path = std::path::Path::new(hash_source);
    if path.is_file() {
        let content = fs::read_to_string(path)?;
        Ok(content.lines().map(String::from).collect())
    } else {
        // Treat as a single hash
        Ok(vec![hash_source.to_string()])
    }
} 