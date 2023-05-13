//! WOTS public keys.

/// An WOTS public key.
#[derive(Eq, PartialEq)]
pub struct PublicKey([[u8; 32]; 32]);

impl PublicKey {
    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [[u8; 32]; 32] {
        self.0
    }
}

/// Construct a `PublicKey` from a bytes.
impl From<[[u8; 32]; 32]> for PublicKey {
    fn from(key: [[u8; 32]; 32]) -> Self {
        Self(key)
    }
}
