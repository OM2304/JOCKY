//! Embedded-payload delivery vehicle (PS: "in-memory execution via native
//! components").
//!
//! `embedded/payload.jcx` is included at COMPILE time via include_bytes! --
//! at runtime the binary decrypts nothing, opens nothing, and simply
//! executes the image straight from its own .rdata section: the payload
//! never exists as a file on disk.
//!
//! Rebuild the embedded payload with:
//!     python -m jocky build examples/hello.jck -o native/vm_rs/embedded/payload.jcx
//!     cargo build --release
//! For an encrypted embed, replace payload.jcx with a .jxp blob and pass
//! JOCKY_EMBED_KEY=<hex> when building (picked up via option_env! at the
//! call site in main.rs if wired that way).

pub const PAYLOAD: &[u8] = include_bytes!("../embedded/payload.jcx");
