//! # Candidate Generation
//!
//! This module is responsible for generating password candidates for the cracker.
//! It implements the core logic for three different attack modes:
//! 1.  **Wordlist (+ Rules):** Reads words from a file and optionally applies a series
//!     of mangling rules to each word.
//! 2.  **Mask:** Generates candidates based on a character mask (e.g., `?d?d?l?l`).
//!
//! The generation is done in separate "producer" threads, which feed candidates
//! into a channel to be consumed by the cracking threads. This decouples generation
//! from cracking and allows for efficient, parallel processing.

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::thread;
use crossbeam_channel::{Sender};
use crate::utils::Session;
use std::sync::{Arc, Mutex};

// --- Rule Engine ---

/// Represents a single password mangling rule operation.
#[derive(Debug, Clone)]
pub enum Rule {
    Lowercase,
    Uppercase,
    Capitalize,
    Append(char),
    Prepend(char),
    ToggleCase, // t
    Reverse, // r
}

/// Parses a line from a rule file into a `Rule` enum.
/// Supports simple rules like 'l' (lowercase), 'c' (capitalize), '^x' (prepend x), etc.
fn parse_rule(line: &str) -> Option<Rule> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None; // Ignore empty lines and comments
    }

    match trimmed.chars().next() {
        Some('l') => Some(Rule::Lowercase),
        Some('u') => Some(Rule::Uppercase),
        Some('c') => Some(Rule::Capitalize),
        Some('t') => Some(Rule::ToggleCase),
        Some('r') => Some(Rule::Reverse),
        Some('$') => trimmed.chars().nth(1).map(Rule::Append),
        Some('^') => trimmed.chars().nth(1).map(Rule::Prepend),
        _ => {
            eprintln!("Warning: Unsupported rule '{}'", trimmed);
            None
        }
    }
}

/// Loads a set of rules from a file.
pub fn load_rules(path: &str) -> io::Result<Vec<Rule>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines().filter_map(|line| line.ok().and_then(|l| parse_rule(&l))).collect())
}

/// Applies a list of rules to a base word.
/// Each rule is applied to the output of the previous rule's variations.
pub fn apply_rules(base_word: &str, rules: &[Rule]) -> Vec<String> {
    let mut variations = vec![base_word.to_string()];
    if rules.is_empty() {
        return variations;
    }

    for rule in rules {
        let mut new_variations_from_rule = Vec::new();
        for var in &variations {
             let transformed = match rule {
                Rule::Lowercase => Some(var.to_lowercase()),
                Rule::Uppercase => Some(var.to_uppercase()),
                Rule::Capitalize => {
                    let mut chars = var.chars();
                    match chars.next() {
                        Some(first) => Some(first.to_uppercase().to_string() + chars.as_str()),
                        None => Some(String::new()),
                    }
                }
                Rule::ToggleCase => Some(var.chars().map(|c| {
                    if c.is_lowercase() { c.to_uppercase().to_string() }
                    else { c.to_lowercase().to_string() }
                }).collect()),
                Rule::Reverse => Some(var.chars().rev().collect()),
                Rule::Append(c) => Some(format!("{}{}", var, c)),
                Rule::Prepend(c) => Some(format!("{}{}", c, var)),
            };
            if let Some(t) = transformed {
                if !variations.contains(&t) && !new_variations_from_rule.contains(&t) {
                     new_variations_from_rule.push(t);
                }
            }
        }
        variations.extend(new_variations_from_rule);
    }

    variations
}

/// Spawns a producer thread that reads a wordlist, applies rules, and sends
/// candidates to the consumers via a channel. It respects session state to resume.
pub fn spawn_producer(
    path: String, 
    rules: Option<Vec<Rule>>, 
    session: Arc<Mutex<Session>>, 
    sender: Sender<String>
) {
    thread::spawn(move || {
        let file = match File::open(Path::new(&path)) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Error: Could not open wordlist file '{}': {}", path, e);
                return;
            }
        };

        let reader = io::BufReader::new(file);

        let mut line_number = 0;
        let starting_offset = session.lock().unwrap().wordlist_offset;

        if starting_offset > 0 {
            println!("⏩ Resuming wordlist from line {}.", starting_offset);
        }

        for line in reader.lines() {
            line_number += 1;
            if line_number < starting_offset {
                continue;
            }

            if let Ok(password) = line {
                let candidates = if let Some(ref rules) = rules {
                    // Apply rules to the base password
                    apply_rules(&password, rules)
                } else {
                    // No rules, just use the password as is
                    vec![password]
                };

                for candidate in candidates {
                    if sender.send(candidate).is_err() {
                        return; // Exit the producer thread
                    }
                }
                
                // Update session progress periodically to avoid too much locking
                if line_number % 1000 == 0 {
                    let mut session_lock = session.lock().unwrap();
                    session_lock.wordlist_offset = line_number;
                }
            }
        }
        
        // Final progress update
        let mut session_lock = session.lock().unwrap();
        session_lock.wordlist_offset = line_number;
    });
}

// --- Mask Attack Engine ---

const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS_CHARS: &[u8] = b"0123456789";
const SPECIAL_CHARS: &[u8] = b"!@#$%^&*()-_+=~`[]{}|:;\"'<>,.?/";

/// An iterator that generates password candidates from a mask (e.g., `?l?u?d`).
/// It works like an odometer, incrementing through all possible character combinations.
pub struct MaskIterator {
    charsets: Vec<&'static [u8]>,
    pub indices: Vec<usize>, // Made public to read state
    done: bool,
}

impl MaskIterator {
    /// Creates a new iterator from a mask string and an optional initial state for resuming.
    pub fn new(mask: &str, initial_indices: Option<Vec<usize>>) -> Result<Self, String> {
        let mut charsets = Vec::new();
        let mut remaining_mask = mask;

        while let Some(i) = remaining_mask.find('?') {
            // Check for literals before the '?'
            if i > 0 {
                return Err("Masks can only contain ?l, ?u, ?d, ?s placeholders for now.".to_string());
            }

            let specifier = remaining_mask.chars().nth(1).ok_or("Mask ends with '?'")?;
            let set = match specifier {
                'l' => LOWERCASE_CHARS,
                'u' => UPPERCASE_CHARS,
                'd' => DIGITS_CHARS,
                's' => SPECIAL_CHARS,
                _ => return Err(format!("Invalid mask specifier: '?{}'", specifier)),
            };
            charsets.push(set);
            // Move to the rest of the mask
            remaining_mask = &remaining_mask[2..];
        }

        if !remaining_mask.is_empty() {
             return Err("Masks can only contain ?l, ?u, ?d, ?s placeholders for now.".to_string());
        }

        let len = charsets.len();
        let indices = if let Some(mut initial) = initial_indices {
            // Validate the saved indices to ensure they match the mask structure
            if initial.len() != len {
                eprintln!("Warning: Session indices length mismatch. Starting mask from the beginning.");
                initial = vec![0; len];
            }
            initial
        } else {
            vec![0; len]
        };

        Ok(Self {
            charsets,
            indices,
            done: len == 0,
        })
    }
}

impl Iterator for MaskIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // 1. Generate the current candidate
        let mut current_pass = String::with_capacity(self.indices.len());
        for (i, &char_index) in self.indices.iter().enumerate() {
            current_pass.push(self.charsets[i][char_index] as char);
        }

        // 2. Increment the indices for the next call
        let mut carry = 1;
        for i in (0..self.indices.len()).rev() {
            if carry == 0 {
                break;
            }
            let new_index = self.indices[i] + 1;
            if new_index >= self.charsets[i].len() {
                self.indices[i] = 0;
                carry = 1;
            } else {
                self.indices[i] = new_index;
                carry = 0;
            }
        }

        // 3. Check if we are done
        if carry == 1 {
            self.done = true;
        }

        Some(current_pass)
    }
}

/// Spawns a producer thread that generates candidates from a mask and sends them
/// to the consumers. It respects session state to resume from a previous position.
pub fn spawn_mask_producer(mask: String, session: Arc<Mutex<Session>>, sender: Sender<String>) {
    thread::spawn(move || {
        let initial_indices = session.lock().unwrap().mask_indices.clone();
        
        if initial_indices.is_some() {
            println!("⏩ Resuming mask attack.");
        }

        match MaskIterator::new(&mask, initial_indices) {
            Ok(mut mask_iterator) => {
                let mut count = 0;
                while let Some(candidate) = mask_iterator.next() {
                    if sender.send(candidate).is_err() {
                        break; // Receiver dropped
                    }
                    count += 1;
                    if count % 10000 == 0 { // Update less frequently for masks
                        let mut session_lock = session.lock().unwrap();
                        session_lock.mask_indices = Some(mask_iterator.indices.clone());
                    }
                }
                 // Final progress update
                let mut session_lock = session.lock().unwrap();
                session_lock.mask_indices = Some(mask_iterator.indices.clone());
            }
            Err(e) => {
                eprintln!("Error creating mask iterator: {}", e);
            }
        }
    });
} 