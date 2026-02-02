use thiserror::Error;

#[derive(Error, Debug)]
pub enum UiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid input")]
    InvalidInput,

    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, UiError>;
