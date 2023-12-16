use std::convert::Infallible;
use std::fmt;
use std::num::NonZeroU32;

use prost::Message;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection};
use secrecy::Secret;
use tempfile::NamedTempFile;

#[cfg(feature = "unstable")]
use tempfile::TempDir;

use zcash_client_backend::data_api::{AccountBalance, WalletRead};
#[allow(deprecated)]
use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{
        self,
        chain::{scan_cached_blocks, BlockSource},
        wallet::{
            create_proposed_transaction, create_spend_to_address,
            input_selection::{GreedyInputSelectorError, InputSelector, Proposal},
            propose_transfer, spend,
        },
        AccountBirthday, WalletSummary, WalletWrite,
    },
    keys::UnifiedSpendingKey,
    proto::compact_formats::{
        self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    },
    wallet::OvkPolicy,
    zip321,
};
use zcash_note_encryption::Domain;
use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, Network, NetworkUpgrade, Parameters},
    memo::MemoBytes,
    sapling::{
        note_encryption::{sapling_note_encryption, SaplingDomain},
        util::generate_random_rseed,
        value::NoteValue,
        Note, Nullifier, PaymentAddress,
    },
    transaction::{
        components::{
            amount::{BalanceError, NonNegativeAmount},
            Amount,
        },
        fees::FeeRule,
        Transaction, TxId,
    },
    zip32::{sapling::DiversifiableFullViewingKey, DiversifierIndex},
};

use crate::{
    chain::init::init_cache_database,
    error::SqliteClientError,
    wallet::{
        commitment_tree, get_wallet_summary, init::init_wallet_db, sapling::tests::test_prover,
        SubtreeScanProgress,
    },
    AccountId, ReceivedNoteId, WalletDb,
};

use super::BlockDb;

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::data_api::wallet::{propose_shielding, shield_transparent_funds},
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "unstable")]
use crate::{
    chain::{init::init_blockmeta_db, BlockMeta},
    FsBlockDb,
};

/// A builder for a `zcash_client_sqlite` test.
pub(crate) struct TestBuilder<Cache> {
    network: Network,
    cache: Cache,
    test_account_birthday: Option<AccountBirthday>,
}

impl TestBuilder<()> {
    /// Constructs a new test.
    pub(crate) fn new() -> Self {
        TestBuilder {
            network: Network::TestNetwork,
            cache: (),
            test_account_birthday: None,
        }
    }

    /// Adds a [`BlockDb`] cache to the test.
    pub(crate) fn with_block_cache(self) -> TestBuilder<BlockCache> {
        TestBuilder {
            network: self.network,
            cache: BlockCache::new(),
            test_account_birthday: self.test_account_birthday,
        }
    }

    /// Adds a [`FsBlockDb`] cache to the test.
    #[cfg(feature = "unstable")]
    pub(crate) fn with_fs_block_cache(self) -> TestBuilder<FsBlockCache> {
        TestBuilder {
            network: self.network,
            cache: FsBlockCache::new(),
            test_account_birthday: self.test_account_birthday,
        }
    }
}

impl<Cache> TestBuilder<Cache> {
    pub(crate) fn with_test_account<F: FnOnce(&Network) -> AccountBirthday>(
        mut self,
        birthday: F,
    ) -> Self {
        self.test_account_birthday = Some(birthday(&self.network));
        self
    }

    /// Builds the state for this test.
    pub(crate) fn build(self) -> TestState<Cache> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), self.network).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        let test_account = if let Some(birthday) = self.test_account_birthday {
            let seed = Secret::new(vec![0u8; 32]);
            let (account, usk) = db_data.create_account(&seed, birthday.clone()).unwrap();
            Some((account, usk, birthday))
        } else {
            None
        };

        TestState {
            cache: self.cache,
            latest_cached_block: None,
            _data_file: data_file,
            db_data,
            test_account,
        }
    }
}

/// The state for a `zcash_client_sqlite` test.
pub(crate) struct TestState<Cache> {
    cache: Cache,
    latest_cached_block: Option<(BlockHeight, BlockHash, u32)>,
    _data_file: NamedTempFile,
    db_data: WalletDb<Connection, Network>,
    test_account: Option<(AccountId, UnifiedSpendingKey, AccountBirthday)>,
}

impl<Cache: TestCache> TestState<Cache>
where
    <Cache::BlockSource as BlockSource>::Error: fmt::Debug,
{
    /// Exposes an immutable reference to the test's [`BlockSource`].
    #[cfg(feature = "unstable")]
    pub(crate) fn cache(&self) -> &Cache::BlockSource {
        self.cache.block_source()
    }

    pub(crate) fn latest_cached_block(&self) -> &Option<(BlockHeight, BlockHash, u32)> {
        &self.latest_cached_block
    }

    /// Creates a fake block at the expected next height containing a single output of the
    /// given value, and inserts it into the cache.
    pub(crate) fn generate_next_block(
        &mut self,
        dfvk: &DiversifiableFullViewingKey,
        req: AddressType,
        value: Amount,
    ) -> (BlockHeight, Cache::InsertResult, Nullifier) {
        let (height, prev_hash, initial_sapling_tree_size) = self
            .latest_cached_block
            .map(|(prev_height, prev_hash, end_size)| (prev_height + 1, prev_hash, end_size))
            .unwrap_or_else(|| (self.sapling_activation_height(), BlockHash([0; 32]), 0));

        let (res, nf) = self.generate_block_at(
            height,
            prev_hash,
            dfvk,
            req,
            value,
            initial_sapling_tree_size,
        );

        (height, res, nf)
    }

    /// Creates a fake block with the given height and hash containing a single output of
    /// the given value, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] will build on it.
    pub(crate) fn generate_block_at(
        &mut self,
        height: BlockHeight,
        prev_hash: BlockHash,
        dfvk: &DiversifiableFullViewingKey,
        req: AddressType,
        value: Amount,
        initial_sapling_tree_size: u32,
    ) -> (Cache::InsertResult, Nullifier) {
        let (cb, nf) = fake_compact_block(
            &self.network(),
            height,
            prev_hash,
            dfvk,
            req,
            value,
            initial_sapling_tree_size,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some((
            height,
            cb.hash(),
            initial_sapling_tree_size
                + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ));

        (res, nf)
    }

    /// Creates a fake block at the expected next height spending the given note, and
    /// inserts it into the cache.
    pub(crate) fn generate_next_block_spending(
        &mut self,
        dfvk: &DiversifiableFullViewingKey,
        note: (Nullifier, Amount),
        to: PaymentAddress,
        value: Amount,
    ) -> (BlockHeight, Cache::InsertResult) {
        let (height, prev_hash, initial_sapling_tree_size) = self
            .latest_cached_block
            .map(|(prev_height, prev_hash, end_size)| (prev_height + 1, prev_hash, end_size))
            .unwrap_or_else(|| (self.sapling_activation_height(), BlockHash([0; 32]), 0));

        let cb = fake_compact_block_spending(
            &self.network(),
            height,
            prev_hash,
            note,
            dfvk,
            to,
            value,
            initial_sapling_tree_size,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some((
            height,
            cb.hash(),
            initial_sapling_tree_size
                + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ));

        (height, res)
    }

    /// Creates a fake block at the expected next height containing only the wallet
    /// transaction with the given txid, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] (or similar) will build on it.
    pub(crate) fn generate_next_block_including(
        &mut self,
        txid: TxId,
    ) -> (BlockHeight, Cache::InsertResult) {
        let tx = self
            .wallet()
            .get_transaction(txid)
            .expect("TxId should exist in the wallet");

        // Index 0 is by definition a coinbase transaction, and the wallet doesn't
        // construct coinbase transactions. So we pretend here that the block has a
        // coinbase transaction that does not have shielded coinbase outputs.
        self.generate_next_block_from_tx(1, &tx)
    }

    /// Creates a fake block at the expected next height containing only the given
    /// transaction, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] will build on it.
    pub(crate) fn generate_next_block_from_tx(
        &mut self,
        tx_index: usize,
        tx: &Transaction,
    ) -> (BlockHeight, Cache::InsertResult) {
        let (height, prev_hash, initial_sapling_tree_size) = self
            .latest_cached_block
            .map(|(prev_height, prev_hash, end_size)| (prev_height + 1, prev_hash, end_size))
            .unwrap_or_else(|| (self.sapling_activation_height(), BlockHash([0; 32]), 0));

        let cb = fake_compact_block_from_tx(
            height,
            prev_hash,
            tx_index,
            tx,
            initial_sapling_tree_size,
            0,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some((
            height,
            cb.hash(),
            initial_sapling_tree_size
                + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ));

        (height, res)
    }

    /// Invokes [`scan_cached_blocks`] with the given arguments, expecting success.
    pub(crate) fn scan_cached_blocks(&mut self, from_height: BlockHeight, limit: usize) {
        assert_matches!(self.try_scan_cached_blocks(from_height, limit), Ok(_));
    }

    /// Invokes [`scan_cached_blocks`] with the given arguments.
    pub(crate) fn try_scan_cached_blocks(
        &mut self,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<
        (),
        data_api::chain::error::Error<
            SqliteClientError,
            <Cache::BlockSource as BlockSource>::Error,
        >,
    > {
        scan_cached_blocks(
            &self.network(),
            self.cache.block_source(),
            &mut self.db_data,
            from_height,
            limit,
        )
    }

    /// Resets the wallet using a new wallet database but with the same cache of blocks,
    /// and returns the old wallet database file.
    ///
    /// This does not recreate accounts, nor does it rescan the cached blocks.
    /// The resulting wallet has no test account.
    /// Before using any `generate_*` method on the reset state, call `reset_latest_cached_block()`.
    pub(crate) fn reset(&mut self) -> NamedTempFile {
        let network = self.network();
        self.latest_cached_block = None;
        let tf = std::mem::replace(&mut self._data_file, NamedTempFile::new().unwrap());
        self.db_data = WalletDb::for_path(self._data_file.path(), network).unwrap();
        self.test_account = None;
        init_wallet_db(&mut self.db_data, None).unwrap();
        tf
    }

    /// Reset the latest cached block to the most recent one in the cache database.
    #[allow(dead_code)]
    pub(crate) fn reset_latest_cached_block(&mut self) {
        self.cache
            .block_source()
            .with_blocks::<_, Infallible>(None, None, |block: CompactBlock| {
                self.latest_cached_block = Some((
                    BlockHeight::from_u32(block.height.try_into().unwrap()),
                    BlockHash::from_slice(block.hash.as_slice()),
                    block.chain_metadata.unwrap().sapling_commitment_tree_size,
                ));
                Ok(())
            })
            .unwrap();
    }
}

impl<Cache> TestState<Cache> {
    /// Exposes an immutable reference to the test's [`WalletDb`].
    pub(crate) fn wallet(&self) -> &WalletDb<Connection, Network> {
        &self.db_data
    }

    /// Exposes a mutable reference to the test's [`WalletDb`].
    pub(crate) fn wallet_mut(&mut self) -> &mut WalletDb<Connection, Network> {
        &mut self.db_data
    }

    /// Exposes the network in use.
    pub(crate) fn network(&self) -> Network {
        self.db_data.params
    }

    /// Convenience method for obtaining the Sapling activation height for the network under test.
    pub(crate) fn sapling_activation_height(&self) -> BlockHeight {
        self.db_data
            .params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height must be known.")
    }

    /// Exposes the test account, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account(&self) -> Option<(AccountId, UnifiedSpendingKey, AccountBirthday)> {
        self.test_account.as_ref().cloned()
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account_sapling(&self) -> Option<DiversifiableFullViewingKey> {
        self.test_account
            .as_ref()
            .and_then(|(_, usk, _)| usk.to_unified_full_viewing_key().sapling().cloned())
    }

    /// Invokes [`create_spend_to_address`] with the given arguments.
    #[allow(deprecated)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn create_spend_to_address(
        &mut self,
        usk: &UnifiedSpendingKey,
        to: &RecipientAddress,
        amount: Amount,
        memo: Option<MemoBytes>,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            GreedyInputSelectorError<BalanceError, ReceivedNoteId>,
            Infallible,
            ReceivedNoteId,
        >,
    > {
        let params = self.network();
        create_spend_to_address(
            &mut self.db_data,
            &params,
            test_prover(),
            usk,
            to,
            amount,
            memo,
            ovk_policy,
            min_confirmations,
        )
    }

    /// Invokes [`spend`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub(crate) fn spend<InputsT>(
        &mut self,
        input_selector: &InputsT,
        usk: &UnifiedSpendingKey,
        request: zip321::TransactionRequest,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        let params = self.network();
        spend(
            &mut self.db_data,
            &params,
            test_prover(),
            input_selector,
            usk,
            request,
            ovk_policy,
            min_confirmations,
        )
    }

    /// Invokes [`propose_transfer`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub(crate) fn propose_transfer<InputsT>(
        &mut self,
        spend_from_account: AccountId,
        input_selector: &InputsT,
        request: zip321::TransactionRequest,
        min_confirmations: NonZeroU32,
    ) -> Result<
        Proposal<InputsT::FeeRule, ReceivedNoteId>,
        data_api::error::Error<
            SqliteClientError,
            Infallible,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        let params = self.network();
        propose_transfer::<_, _, _, Infallible>(
            &mut self.db_data,
            &params,
            spend_from_account,
            input_selector,
            request,
            min_confirmations,
        )
    }

    /// Invokes [`propose_shielding`] with the given arguments.
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub(crate) fn propose_shielding<InputsT>(
        &mut self,
        input_selector: &InputsT,
        shielding_threshold: NonNegativeAmount,
        from_addrs: &[TransparentAddress],
        min_confirmations: NonZeroU32,
    ) -> Result<
        Proposal<InputsT::FeeRule, ReceivedNoteId>,
        data_api::error::Error<
            SqliteClientError,
            Infallible,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        let params = self.network();
        propose_shielding::<_, _, _, Infallible>(
            &mut self.db_data,
            &params,
            input_selector,
            shielding_threshold,
            from_addrs,
            min_confirmations,
        )
    }

    /// Invokes [`create_proposed_transaction`] with the given arguments.
    pub(crate) fn create_proposed_transaction<FeeRuleT>(
        &mut self,
        usk: &UnifiedSpendingKey,
        ovk_policy: OvkPolicy,
        proposal: Proposal<FeeRuleT, ReceivedNoteId>,
        min_confirmations: NonZeroU32,
        change_memo: Option<MemoBytes>,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            Infallible,
            FeeRuleT::Error,
            ReceivedNoteId,
        >,
    >
    where
        FeeRuleT: FeeRule,
    {
        let params = self.network();
        create_proposed_transaction::<_, _, Infallible, _>(
            &mut self.db_data,
            &params,
            test_prover(),
            usk,
            ovk_policy,
            proposal,
            min_confirmations,
            change_memo,
        )
    }

    /// Invokes [`shield_transparent_funds`] with the given arguments.
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    pub(crate) fn shield_transparent_funds<InputsT>(
        &mut self,
        input_selector: &InputsT,
        shielding_threshold: NonNegativeAmount,
        usk: &UnifiedSpendingKey,
        from_addrs: &[TransparentAddress],
        memo: &MemoBytes,
        min_confirmations: NonZeroU32,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        let params = self.network();
        shield_transparent_funds(
            &mut self.db_data,
            &params,
            test_prover(),
            input_selector,
            shielding_threshold,
            usk,
            from_addrs,
            memo,
            min_confirmations,
        )
    }

    fn with_account_balance<T, F: FnOnce(&AccountBalance) -> T>(
        &self,
        account: AccountId,
        min_confirmations: u32,
        f: F,
    ) -> T {
        let binding =
            get_wallet_summary(&self.wallet().conn, min_confirmations, &SubtreeScanProgress)
                .unwrap()
                .unwrap();

        f(binding.account_balances().get(&account).unwrap())
    }

    pub(crate) fn get_total_balance(&self, account: AccountId) -> NonNegativeAmount {
        self.with_account_balance(account, 0, |balance| balance.total())
    }

    pub(crate) fn get_spendable_balance(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.sapling_balance.spendable_value
        })
    }

    pub(crate) fn get_pending_shielded_balance(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.sapling_balance.value_pending_spendability
                + balance.sapling_balance.change_pending_confirmation
        })
        .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn get_pending_change(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.sapling_balance.change_pending_confirmation
        })
    }

    pub(crate) fn get_wallet_summary(&self, min_confirmations: u32) -> Option<WalletSummary> {
        get_wallet_summary(&self.wallet().conn, min_confirmations, &SubtreeScanProgress).unwrap()
    }
}

#[allow(dead_code)]
pub(crate) enum AddressType {
    DefaultExternal,
    DiversifiedExternal(DiversifierIndex),
    Internal,
}

/// Create a fake CompactBlock at the given height, containing a single output paying
/// an address. Returns the CompactBlock and the nullifier for the new note.
pub(crate) fn fake_compact_block<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    prev_hash: BlockHash,
    dfvk: &DiversifiableFullViewingKey,
    req: AddressType,
    value: Amount,
    initial_sapling_tree_size: u32,
) -> (CompactBlock, Nullifier) {
    let to = match req {
        AddressType::DefaultExternal => dfvk.default_address().1,
        AddressType::DiversifiedExternal(idx) => dfvk.find_address(idx).unwrap().1,
        AddressType::Internal => dfvk.change_address().1,
    };

    // Create a fake Note for the account
    let mut rng = OsRng;
    let rseed = generate_random_rseed(params, height, &mut rng);
    let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
    let encryptor = sapling_note_encryption::<_, Network>(
        Some(dfvk.fvk().ovk),
        note.clone(),
        MemoBytes::empty(),
        &mut rng,
    );
    let cmu = note.cmu().to_bytes().to_vec();
    let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
        .0
        .to_vec();
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    // Create a fake CompactBlock containing the note
    let cout = CompactSaplingOutput {
        cmu,
        ephemeral_key,
        ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
    };
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;
    ctx.outputs.push(cout);
    let mut cb = CompactBlock {
        hash: {
            let mut hash = vec![0; 32];
            rng.fill_bytes(&mut hash);
            hash
        },
        height: height.into(),
        ..Default::default()
    };
    cb.prev_hash.extend_from_slice(&prev_hash.0);
    cb.vtx.push(ctx);
    cb.chain_metadata = Some(compact::ChainMetadata {
        sapling_commitment_tree_size: initial_sapling_tree_size
            + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ..Default::default()
    });
    (cb, note.nf(&dfvk.fvk().vk.nk, 0))
}

/// Create a fake CompactBlock at the given height containing only the given transaction.
pub(crate) fn fake_compact_block_from_tx(
    height: BlockHeight,
    prev_hash: BlockHash,
    tx_index: usize,
    tx: &Transaction,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
) -> CompactBlock {
    // Create a fake CompactTx containing the transaction.
    let mut ctx = CompactTx {
        index: tx_index as u64,
        hash: tx.txid().as_ref().to_vec(),
        ..Default::default()
    };

    if let Some(bundle) = tx.sapling_bundle() {
        for spend in bundle.shielded_spends() {
            ctx.spends.push(spend.into());
        }
        for output in bundle.shielded_outputs() {
            ctx.outputs.push(output.into());
        }
    }
    if let Some(bundle) = tx.orchard_bundle() {
        for action in bundle.actions() {
            ctx.actions.push(action.into());
        }
    }

    fake_compact_block_from_compact_tx(
        ctx,
        height,
        prev_hash,
        initial_sapling_tree_size,
        initial_orchard_tree_size,
    )
}

/// Create a fake CompactBlock at the given height, spending a single note from the
/// given address.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fake_compact_block_spending<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    prev_hash: BlockHash,
    (nf, in_value): (Nullifier, Amount),
    dfvk: &DiversifiableFullViewingKey,
    to: PaymentAddress,
    value: Amount,
    initial_sapling_tree_size: u32,
) -> CompactBlock {
    let mut rng = OsRng;
    let rseed = generate_random_rseed(params, height, &mut rng);

    // Create a fake CompactBlock containing the note
    let cspend = CompactSaplingSpend { nf: nf.to_vec() };
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;
    ctx.spends.push(cspend);

    // Create a fake Note for the payment
    ctx.outputs.push({
        let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        }
    });

    // Create a fake Note for the change
    ctx.outputs.push({
        let change_addr = dfvk.default_address().1;
        let rseed = generate_random_rseed(params, height, &mut rng);
        let note = Note::from_parts(
            change_addr,
            NoteValue::from_raw((in_value - value).unwrap().into()),
            rseed,
        );
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        }
    });

    fake_compact_block_from_compact_tx(ctx, height, prev_hash, initial_sapling_tree_size, 0)
}

pub(crate) fn fake_compact_block_from_compact_tx(
    ctx: CompactTx,
    height: BlockHeight,
    prev_hash: BlockHash,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
) -> CompactBlock {
    let mut rng = OsRng;
    let mut cb = CompactBlock {
        hash: {
            let mut hash = vec![0; 32];
            rng.fill_bytes(&mut hash);
            hash
        },
        height: height.into(),
        ..Default::default()
    };
    cb.prev_hash.extend_from_slice(&prev_hash.0);
    cb.vtx.push(ctx);
    cb.chain_metadata = Some(compact::ChainMetadata {
        sapling_commitment_tree_size: initial_sapling_tree_size
            + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        orchard_commitment_tree_size: initial_orchard_tree_size
            + cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum::<u32>(),
    });
    cb
}

/// Trait used by tests that require a block cache.
pub(crate) trait TestCache {
    type BlockSource: BlockSource;
    type InsertResult;

    /// Exposes the block cache as a [`BlockSource`].
    fn block_source(&self) -> &Self::BlockSource;

    /// Inserts a CompactBlock into the cache DB.
    fn insert(&self, cb: &CompactBlock) -> Self::InsertResult;
}

pub(crate) struct BlockCache {
    _cache_file: NamedTempFile,
    db_cache: BlockDb,
}

impl BlockCache {
    fn new() -> Self {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        BlockCache {
            _cache_file: cache_file,
            db_cache,
        }
    }
}

impl TestCache for BlockCache {
    type BlockSource = BlockDb;
    type InsertResult = ();

    fn block_source(&self) -> &Self::BlockSource {
        &self.db_cache
    }

    fn insert(&self, cb: &CompactBlock) {
        let cb_bytes = cb.encode_to_vec();
        self.db_cache
            .0
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(params![u32::from(cb.height()), cb_bytes,])
            .unwrap();
    }
}

#[cfg(feature = "unstable")]
pub(crate) struct FsBlockCache {
    db_meta: FsBlockDb,
    storage: crate::chain::DefaultCompactBlockStorage,
}

#[cfg(feature = "unstable")]
impl FsBlockCache {
    fn new() -> Self {
        let fsblockdb_root = tempfile::tempdir().unwrap();
        let storage = crate::chain::DefaultCompactBlockStorage::new(
            fsblockdb_root.path().to_path_buf().join("blocks"),
        )
        .unwrap();
        let mut db_meta =
            FsBlockDb::for_path_storage(&fsblockdb_root, Box::new(storage.clone())).unwrap();
        init_blockmeta_db(&mut db_meta).unwrap();

        FsBlockCache { db_meta, storage }
    }
}

#[cfg(feature = "unstable")]
impl TestCache for FsBlockCache {
    type BlockSource = FsBlockDb;
    type InsertResult = BlockMeta;

    fn block_source(&self) -> &Self::BlockSource {
        &self.db_meta
    }

    fn insert(&self, cb: &CompactBlock) -> Self::InsertResult {
        let meta = BlockMeta {
            height: cb.height(),
            block_hash: cb.hash(),
            block_time: cb.time,
            sapling_outputs_count: cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum(),
            orchard_actions_count: cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum(),
        };

        self.storage
            .put_compact_block(&meta, &cb.encode_to_vec())
            .unwrap();

        meta
    }
}
