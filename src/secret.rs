//! WOTS secret keys.
use crate::signature::Signature;
use rand::{CryptoRng, RngCore};
use sha256_rs::*;

/// An WOTS secret key.
#[derive(Eq, PartialEq)]
pub struct SecretKey([[u8; 32]; 32]);

impl SecretKey {
    /// Generate a `SecretKey` from a `csprng`.
    ///
    /// # Example
    ///
    /// ```
    /// use rand::rngs::OsRng;
    /// use wots_rs::SecretKey;
    ///
    /// let mut csprng = OsRng{};
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    ///
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand_os::OsRng`.
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut secret_key = [[0u8; 32]; 32];

        for key in secret_key.iter_mut() {
            let mut temp = [0u8; 32];
            csprng.fill_bytes(&mut temp);
            *key = temp;
        }

        SecretKey(secret_key)
    }

    // Sign a `message` with this `SecretKey` using the
    /// WOTS algorithm.
    ///
    /// # Inputs
    ///
    /// * `message` in bytes representation.
    ///
    /// # Returns
    ///
    /// An WOTS [`Signature`] on the `message`.
    ///
    /// # Example
    ///
    /// ```
    /// use rand::rngs::OsRng;
    /// use wots_rs::SecretKey;
    ///
    /// let mut csprng = OsRng{};
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    ///
    /// let message = b"hello";
    /// let signature = secret_key.sign(message);
    ///
    /// ```
    pub fn sign(&self, message: &[u8]) -> Signature {
        let secret_key = self.0;

        let mut signature = [[0u8; 32]; 32];
        let hash = sha256(message);

        for (i, s) in signature.iter_mut().enumerate() {
            let mut key = secret_key[i];
            let n = hash[i];

            for _ in 0..256 - n as usize {
                key = sha256(&key);
            }

            *s = key;
        }

        Signature::from(signature)
    }

    /// Convert this secret key to a byte array.
    pub fn to_bytes(&self) -> [[u8; 32]; 32] {
        self.0
    }
}

/// Construct a `SecretKey` from a bytes.
impl From<[[u8; 32]; 32]> for SecretKey {
    fn from(value: [[u8; 32]; 32]) -> Self {
        Self(value)
    }
}
