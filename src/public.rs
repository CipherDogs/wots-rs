//! WOTS public keys.
use crate::{secret::SecretKey, signature::Signature};
use sha256_rs::*;

/// An WOTS public key.
#[derive(Eq, PartialEq)]
pub struct PublicKey([[u8; 32]; 32]);

impl PublicKey {
    /// Verify a `signature` on a `message` using the WOTS algorithm.
    ///
    /// # Inputs
    ///
    /// * `message` in bytes representation.
    /// * `signature` is a purported WOTS [`Signature`] on the `message`.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `signature` was a valid signature created by this
    /// `SecretKey` on the `message`.
    ///
    /// # Example
    ///
    /// ```
    /// use rand::rngs::OsRng;
    /// use wots_rs::{PublicKey, SecretKey};
    ///
    /// let mut csprng = OsRng{};
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// let public_key: PublicKey = PublicKey::from(&secret_key);
    ///
    /// let message = b"hello";
    /// let signature = secret_key.sign(message);
    ///
    /// assert!(public_key.verify(message, signature));
    ///
    /// ```
    pub fn verify(&self, message: &[u8], signature: Signature) -> bool {
        let signature = signature.to_bytes();

        let mut public_key = [[0u8; 32]; 32];
        let hash = sha256(message);

        for (i, key) in public_key.iter_mut().enumerate() {
            let mut s = signature[i];
            let n = hash[i];

            for _ in 0..n as usize {
                s = sha256(&s);
            }

            *key = s;
        }

        self.0 == public_key
    }

    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [[u8; 32]; 32] {
        self.0
    }
}

/// Construct a `PublicKey` from a bytes.
impl From<[[u8; 32]; 32]> for PublicKey {
    fn from(value: [[u8; 32]; 32]) -> Self {
        Self(value)
    }
}

/// Construct a `PublicKey` from a `SecretKey`.
impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(value: &SecretKey) -> Self {
        let bytes = value.to_bytes();
        let mut public_key = [[0u8; 32]; 32];

        for (i, key) in public_key.iter_mut().enumerate() {
            let mut skey = bytes[i];

            for _ in 0..256 {
                skey = sha256(&skey);
            }

            *key = skey;
        }

        PublicKey(public_key)
    }
}
