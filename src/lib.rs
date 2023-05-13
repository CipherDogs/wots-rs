//! wots-rs
//!
//! Implementation of the Winternitz One-time Signature Scheme made using Rust
//!
//! # Example
//!
//! ```
//! use rand::rngs::OsRng;
//! use wots_rs::Keypair;
//!
//! let mut csprng = OsRng{};
//! let keypair: Keypair = Keypair::generate(&mut csprng);
//!
//! let message = b"hello";
//! let signature = keypair.sign(message);
//!
//! assert!(keypair.verify(message, signature));
//!
//! ```
mod keypair;
mod public;
mod secret;
mod signature;

pub use keypair::*;
pub use public::*;
pub use secret::*;
pub use signature::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn it_works() {
        let message = b"hello";

        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, signature));
    }
}
