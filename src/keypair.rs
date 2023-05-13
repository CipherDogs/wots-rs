//! WOTS keypairs.
use crate::{public::PublicKey, secret::SecretKey, signature::Signature};
use rand::{CryptoRng, RngCore};
use sha256_rs::*;

const EMPTY: [[u8; 32]; 32] = [[0u8; 32]; 32];

/// An WOTS keypair.
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl Keypair {
    /// Generate an WOTS keypair.
    ///
    /// # Example
    ///
    /// ```
    /// use rand::rngs::OsRng;
    /// use wots_rs::Keypair;
    ///
    /// let mut csprng = OsRng{};
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
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
        let mut secret_key = EMPTY;
        let mut public_key = EMPTY;

        for key in secret_key.iter_mut() {
            let mut temp = [0u8; 32];
            csprng.fill_bytes(&mut temp);
            *key = temp;
        }

        for (i, key) in public_key.iter_mut().enumerate() {
            let mut skey = secret_key[i];

            for _ in 0..256 {
                skey = sha256(&skey);
            }

            *key = skey;
        }

        Keypair {
            secret: SecretKey::from(secret_key),
            public: PublicKey::from(public_key),
        }
    }

    /// Sign a `message` with this `Keypair` using the
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
    /// use wots_rs::Keypair;
    ///
    /// let mut csprng = OsRng{};
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    ///
    /// let message = b"hello";
    /// let signature = keypair.sign(message);
    ///
    /// ```
    pub fn sign(&self, message: &[u8]) -> Signature {
        let secret_key = self.secret.to_bytes();

        let mut signature = EMPTY;
        let hash = sha256(message);

        for (i, s) in signature.iter_mut().enumerate() {
            let mut skey = secret_key[i];
            let n = hash[i];

            for _ in 0..256 - n as usize {
                skey = sha256(&skey);
            }

            *s = skey;
        }

        Signature::from(signature)
    }

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
    /// `Keypair` on the `message`.
    ///
    /// # Example
    ///
    /// ```
    /// use rand::rngs::OsRng;
    /// use wots_rs::Keypair;
    ///
    /// let mut csprng = OsRng{};
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    ///
    /// let message = b"hello";
    /// let signature = keypair.sign(message);
    ///
    /// assert!(keypair.verify(message, signature));
    ///
    /// ```
    pub fn verify(&self, message: &[u8], signature: Signature) -> bool {
        let signature = signature.to_bytes();

        let mut pkey = EMPTY;
        let hash = sha256(message);

        for (i, key) in pkey.iter_mut().enumerate() {
            let mut s = signature[i];
            let n = hash[i];

            for _ in 0..n as usize {
                s = sha256(&s);
            }

            *key = s;
        }

        self.public == PublicKey::from(pkey)
    }
}
