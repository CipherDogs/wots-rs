//! WOTS secret keys.

/// An WOTS secret key.
#[derive(Eq, PartialEq)]
pub struct SecretKey([[u8; 32]; 32]);

impl SecretKey {
    /// Convert this secret key to a byte array.
    pub fn to_bytes(&self) -> [[u8; 32]; 32] {
        self.0
    }
}

/// Construct a `SecretKey` from a bytes.
impl From<[[u8; 32]; 32]> for SecretKey {
    fn from(key: [[u8; 32]; 32]) -> Self {
        Self(key)
    }
}
