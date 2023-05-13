//! WOTS keypairs.
use crate::{public::PublicKey, secret::SecretKey, signature::Signature};
use rand::{CryptoRng, RngCore};

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
        let sk = SecretKey::generate(csprng);
        let pk = PublicKey::from(&sk);

        Keypair {
            secret: sk,
            public: pk,
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
        self.secret.sign(message)
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
        self.public.verify(message, signature)
    }
}
