//! # GPU-Accelerated Cracker
//!
//! This module provides a `Verifier` implementation that uses a system's GPU
//! via the OpenCL framework to accelerate hash verification.
//!
//! ## Workflow
//! 1.  Finds an available GPU device.
//! 2.  Creates an OpenCL context and command queue.
//! 3.  Loads the Argon2 OpenCL kernel source from `src/opencl/argon2_kernel.cl`.
//! 4.  Compiles the kernel for the target device.
//! 5.  When `verify_batch` is called, it prepares memory buffers for passwords,
//!     salts, and outputs.
//! 6.  It enqueues the kernel for execution on the GPU.
//! 7.  Reads the results back and compares them against the target hash.
//!
//! ## Current Limitations
//! - **Single Hash:** The current implementation only supports cracking one hash at a time.
//!   The kernel and buffer management logic are simplified to handle the parameters
//!   of only the *first* hash loaded by the application.
//! - **Error Handling:** OpenCL error handling is simplified for clarity. A production
//!   system would require more robust error checking for buffer creation and kernel calls.

use crate::cracker::{TargetHash, Verifier};
use crate::utils::Potfile;
use base64ct::{Base64, Encoding as _};
use opencl3::command_queue::{CommandQueue, CL_QUEUE_PROFILING_ENABLE};
use opencl3::context::Context;
use opencl3::device::{get_all_devices, Device, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_WRITE_ONLY, CL_MEM_COPY_HOST_PTR};
use opencl3::program::Program;
use opencl3::types::{cl_uint, CL_TRUE};
use std::error::Error;
use std::ffi::c_void;
use std::fs;
use std::sync::{Arc, Mutex};

const KERNEL_SOURCE_PATH: &str = "src/opencl/argon2_kernel.cl";
const MAX_PWD_LENGTH: usize = 64;
const BATCH_SIZE: usize = 4096;

/// A verifier that uses OpenCL to run checks on a GPU.
/// NOTE: This is a simplified implementation that only supports cracking
/// the *first* hash provided.
pub struct GpuVerifier {
    context: Context,
    queue: CommandQueue,
    kernel: Kernel,
    potfile: Arc<Mutex<Potfile>>,
    target_hash: TargetHash,
    candidate_buffer: Mutex<Vec<String>>,
}

impl GpuVerifier {
    /// Creates a new GpuVerifier, initializing the OpenCL context and compiling the kernel.
    pub fn new(
        targets: Arc<Vec<TargetHash>>,
        potfile: Arc<Mutex<Potfile>>,
    ) -> Result<Self, Box<dyn Error>> {
        if targets.is_empty() {
            return Err("No hashes to crack.".into());
        }

        let target_hash = targets[0].clone();
        if targets.len() > 1 {
            println!("Warning: GPU mode currently only supports cracking one hash at a time. Only the first hash '{}' will be checked.", target_hash.hash_string);
        }

        let device_id = *get_all_devices(CL_DEVICE_TYPE_ALL)?
            .first()
            .ok_or("No OpenCL device found")?;
        let device = Device::new(device_id);
        let context = Context::from_device(&device)?;
        
        let queue = unsafe {
            CommandQueue::create_with_properties(&context, device_id, CL_QUEUE_PROFILING_ENABLE, 0)?
        };

        let kernel_source = fs::read_to_string(KERNEL_SOURCE_PATH)?;
        let program = Program::create_and_build_from_source(&context, &kernel_source, "")?;
        let kernel = Kernel::create(&program, "argon2_kernel")?;

        Ok(GpuVerifier {
            context,
            queue,
            kernel,
            potfile,
            target_hash,
            candidate_buffer: Mutex::new(Vec::with_capacity(BATCH_SIZE)),
        })
    }

    /// The actual batch verification logic. This is called by `verify` and `flush`.
    fn process_batch(&self, candidates: &[String]) {
        if candidates.is_empty() { return; }
        if self.potfile.lock().unwrap().contains(&self.target_hash.hash_string) { return; }

        let batch_size = candidates.len();
        let passwords_buffer: Vec<u8> = candidates.iter().flat_map(|p| {
            let mut bytes = p.as_bytes().to_vec();
            bytes.resize(MAX_PWD_LENGTH, 0);
            bytes
        }).collect();

        // --- Correctly parse all parameters from the hash string ---
        let mut m_cost: u32 = 0;
        let mut t_cost: u32 = 0;
        let mut p_cost: u32 = 0;
        for (name, value) in self.target_hash.parsed_hash.params.iter() {
            match name.as_str() {
                "m" => m_cost = value.as_str().parse().expect("Invalid 'm' cost"),
                "t" => t_cost = value.as_str().parse().expect("Invalid 't' cost"),
                "p" => p_cost = value.as_str().parse().expect("Invalid 'p' cost"),
                _ => {}
            }
        }

        let salt_b64 = self.target_hash.parsed_hash.salt.as_ref().expect("Hash has no salt");
        let salt = Base64::decode_vec(salt_b64.as_str()).expect("Failed to decode salt");

        let hash_len = self.target_hash.parsed_hash.hash.as_ref().unwrap().len() as cl_uint;
        let alg_type = match self.target_hash.parsed_hash.algorithm.as_str() {
            "argon2i" => 0,
            "argon2d" => 1,
            "argon2id" => 2,
            _ => panic!("Unsupported Argon2 variant"),
        };

        unsafe {
            let pass_buffer = Buffer::<u8>::create(&self.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, passwords_buffer.len(), passwords_buffer.as_ptr() as *mut _).unwrap();
            let salt_buffer = Buffer::<u8>::create(&self.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, salt.len(), salt.as_ptr() as *mut _).unwrap();
            let out_buffer = Buffer::<u8>::create(&self.context, CL_MEM_WRITE_ONLY, batch_size * hash_len as usize, std::ptr::null_mut()).unwrap();

            let kernel_event = ExecuteKernel::new(&self.kernel)
                .set_arg(&pass_buffer)
                .set_arg_svm(std::ptr::null_mut::<c_void>())
                .set_arg(&out_buffer)
                .set_arg(&salt_buffer)
                .set_arg(&(salt.len() as cl_uint))
                .set_arg(&t_cost)
                .set_arg(&m_cost)
                .set_arg(&p_cost) // Use p_cost here
                .set_arg(&(batch_size as cl_uint))
                .set_arg(&hash_len)
                .set_arg(&alg_type)
                .set_arg(&(19 as cl_uint)) // Version
                .set_global_work_size(batch_size)
                .enqueue_nd_range(&self.queue).unwrap();
            
            let mut results = vec![0u8; batch_size * hash_len as usize];
            self.queue.enqueue_read_buffer(&out_buffer, CL_TRUE, 0, &mut results, &[kernel_event.get()]).unwrap();

            for i in 0..batch_size {
                let offset = i * hash_len as usize;
                let computed_hash = &results[offset..offset + hash_len as usize];
                if computed_hash == self.target_hash.parsed_hash.hash.as_ref().unwrap().as_ref() {
                    let password = &candidates[i];
                    let mut potfile_lock = self.potfile.lock().unwrap();
                    if !potfile_lock.contains(&self.target_hash.hash_string) {
                        println!("\n✅ Success! Found: {}:{}", self.target_hash.hash_string, password);
                        potfile_lock.add(&self.target_hash.hash_string, password).expect("Failed to write to potfile");
                        break; 
                    }
                }
            }
        }
    }
}

impl Verifier for GpuVerifier {
    fn verify(&self, candidate: &str) {
        let mut buffer = self.candidate_buffer.lock().unwrap();
        buffer.push(candidate.to_string());
        if buffer.len() >= BATCH_SIZE {
            let batch_to_process = buffer.clone();
            buffer.clear();
            drop(buffer); // Release lock before processing
            self.process_batch(&batch_to_process);
        }
    }
    
    fn flush(&self) {
        let mut buffer = self.candidate_buffer.lock().unwrap();
        let batch_to_process = buffer.clone();
        buffer.clear();
        drop(buffer);
        if !batch_to_process.is_empty() {
            self.process_batch(&batch_to_process);
        }
    }
}

// We must manually implement Send and Sync because of the raw pointers in the OpenCL types.
// This is generally safe as long as the OpenCL context/queue is used correctly
// (i.e., not creating/releasing objects from different threads without synchronization).
// Our usage pattern is safe.
unsafe impl Send for GpuVerifier {}
unsafe impl Sync for GpuVerifier {} 