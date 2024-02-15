use std::collections::HashMap;

use sapling::note_encryption::{
    try_sapling_note_decryption, try_sapling_output_recovery, PreparedIncomingViewingKey,
};
use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::Transaction,
    zip32::Scope,
};

use crate::keys::UnifiedFullViewingKey;

/// An enumeration of the possible relationships a TXO can have to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferType {
    /// The output was received on one of the wallet's external addresses via decryption using the
    /// associated incoming viewing key, or at one of the wallet's transparent addresses.
    Incoming,
    /// The output was received on one of the wallet's internal-only shielded addresses via trial
    /// decryption using one of the wallet's internal incoming viewing keys.
    WalletInternal,
    /// The output was decrypted using one of the wallet's outgoing viewing keys, or was created
    /// in a transaction constructed by this wallet.
    Outgoing,
}

/// A decrypted shielded output.
pub struct DecryptedOutput<Note, AccountId> {
    /// The index of the output within [`shielded_outputs`].
    ///
    /// [`shielded_outputs`]: zcash_primitives::transaction::TransactionData
    pub index: usize,
    /// The note within the output.
    pub note: Note,
    /// The account that decrypted the note.
    pub account: AccountId,
    /// The memo bytes included with the note.
    pub memo: MemoBytes,
    /// True if this output was recovered using an [`OutgoingViewingKey`], meaning that
    /// this is a logical output of the transaction.
    ///
    /// [`OutgoingViewingKey`]: sapling::keys::OutgoingViewingKey
    pub transfer_type: TransferType,
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`UnifiedFullViewingKey`]s.
pub fn decrypt_transaction<P: consensus::Parameters, A: Clone>(
    params: &P,
    height: BlockHeight,
    tx: &Transaction,
    ufvks: &HashMap<A, UnifiedFullViewingKey>,
) -> Vec<DecryptedOutput<sapling::Note, A>> {
    let zip212_enforcement = consensus::sapling_zip212_enforcement(params, height);
    tx.sapling_bundle()
        .iter()
        .flat_map(|bundle| {
            ufvks
                .iter()
                .flat_map(move |(account, ufvk)| {
                    ufvk.sapling()
                        .into_iter()
                        .map(|dfvk| (account.to_owned(), dfvk))
                })
                .flat_map(move |(account, dfvk)| {
                    let ivk_external =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External));
                    let ivk_internal =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
                    let ovk = dfvk.fvk().ovk;

                    bundle
                        .shielded_outputs()
                        .iter()
                        .enumerate()
                        .flat_map(move |(index, output)| {
                            let account = account.clone();
                            try_sapling_note_decryption(&ivk_external, output, zip212_enforcement)
                                .map(|ret| (ret, TransferType::Incoming))
                                .or_else(|| {
                                    try_sapling_note_decryption(
                                        &ivk_internal,
                                        output,
                                        zip212_enforcement,
                                    )
                                    .map(|ret| (ret, TransferType::WalletInternal))
                                })
                                .or_else(|| {
                                    try_sapling_output_recovery(&ovk, output, zip212_enforcement)
                                        .map(|ret| (ret, TransferType::Outgoing))
                                })
                                .into_iter()
                                .map(move |((note, _, memo), transfer_type)| DecryptedOutput {
                                    index,
                                    note,
                                    account: account.clone(),
                                    memo: MemoBytes::from_bytes(&memo).expect("correct length"),
                                    transfer_type,
                                })
                        })
                })
        })
        .collect()
}
