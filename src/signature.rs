//! WOTS signature.

/// An WOTS signature.
#[derive(Eq, PartialEq)]
pub struct Signature([[u8; 32]; 32]);

impl Signature {
    /// Convert this signature to a byte array.
    pub fn to_bytes(&self) -> [[u8; 32]; 32] {
        self.0
    }
}

/// Construct a `Signature` from a bytes.
impl From<[[u8; 32]; 32]> for Signature {
    fn from(key: [[u8; 32]; 32]) -> Self {
        Self(key)
    }
}
