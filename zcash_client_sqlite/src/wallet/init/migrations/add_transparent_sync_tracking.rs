use std::collections::HashSet;

use rusqlite::Transaction;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{addresses_table, full_account_ids};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xb6ce8980_00c9_4985_9e0c_90a4b11841be);

pub(crate) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [
            addresses_table::MIGRATION_ID,
            full_account_ids::MIGRATION_ID,
        ]
        .into_iter()
        .collect()
    }

    fn description(&self) -> &'static str {
        "Adds the last_downloaded_transparent column to the addresses table."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "ALTER TABLE addresses ADD COLUMN last_downloaded_transparent_block INTEGER;",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "ALTER TABLE addresses DROP COLUMN last_downloaded_transparent_block;",
        )?;
        Ok(())
    }
}
