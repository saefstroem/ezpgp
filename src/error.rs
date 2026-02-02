use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("Contacts error: {0}")]
    Contacts(#[from] crate::contacts::ContactsError),

    #[error("UI error: {0}")]
    Ui(#[from] crate::ui::UiError),

    #[error("Home directory not found")]
    HomeNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Crypto(crate::crypto::CryptoError::Other(err.to_string()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
