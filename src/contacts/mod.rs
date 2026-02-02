mod error;

pub use error::{ContactsError, Result};

use redb::{Database, ReadableTable, TableDefinition};
use sequoia_openpgp::{parse::Parse, Cert};
use std::path::Path;

const CONTACTS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("contacts");

pub struct ContactBook {
    db: Database,
}

#[derive(Clone)]
pub struct Contact {
    pub name: String,
    pub public_key: String,
}

impl ContactBook {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }

    pub fn add(&self, name: &str, public_key: &str) -> Result<()> {
        // Validate the public key
        Cert::from_bytes(public_key.as_bytes())?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CONTACTS_TABLE)?;
            table.insert(name, public_key)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            // If table doesn't exist, there's nothing to remove
            let mut table = match write_txn.open_table(CONTACTS_TABLE) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => {
                    return Err(ContactsError::NotFound(name.to_string()));
                }
                Err(e) => return Err(e.into()),
            };
            table.remove(name)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Contact>> {
        let read_txn = self.db.begin_read()?;

        // Try to open the table, return empty list if it doesn't exist
        let table = match read_txn.open_table(CONTACTS_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut contacts = Vec::new();
        for entry in table.iter()? {
            let (name, pubkey) = entry?;
            contacts.push(Contact {
                name: name.value().to_string(),
                public_key: pubkey.value().to_string(),
            });
        }

        Ok(contacts)
    }

}
