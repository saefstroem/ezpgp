use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContactsError {
    #[error("Database error: {0}")]
    Database(#[from] redb::Error),

    #[error("Database error: {0}")]
    DatabaseError(#[from] redb::DatabaseError),

    #[error("Commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("Transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    #[error("Table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("Storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("Contact not found: {0}")]
    NotFound(String),

    #[error("Invalid public key: {0}")]
    InvalidKey(#[from] sequoia_openpgp::Error),
}

impl From<anyhow::Error> for ContactsError {
    fn from(err: anyhow::Error) -> Self {
        ContactsError::InvalidKey(sequoia_openpgp::Error::InvalidOperation(err.to_string()))
    }
}

pub type Result<T> = std::result::Result<T, ContactsError>;
