//! jocky-rs — native (Rust) VM for JOCKY JY_IMG01 bytecode images.
//!
//! Dependency-free (std only). Executes the SAME container the Python VM
//! runs: reads the portable CPOR constant-pool section, decodes the
//! permuted opcode table, verifies JYCRYPT1 blobs, and mirrors the exact
//! Python-VM output semantics (see value.rs for the parity layer).

pub mod bytecode;
pub mod crypto;
pub mod payload;
pub mod sha256;
pub mod value;
pub mod vm;

pub use payload::PAYLOAD;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
