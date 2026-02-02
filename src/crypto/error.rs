use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Sequoia error: {0}")]
    Sequoia(#[from] sequoia_openpgp::Error),

    #[error("Error: {0}")]
    Other(String),

    #[error("Invalid certificate")]
    InvalidCert,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("No suitable key found")]
    NoSuitableKey,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<anyhow::Error> for CryptoError {
    fn from(err: anyhow::Error) -> Self {
        CryptoError::Other(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;
