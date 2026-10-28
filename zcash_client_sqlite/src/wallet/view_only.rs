//! View-only scanning: notes and spends are stored, note commitment trees are not.

use assert_matches::assert_matches;
use rusqlite::{Connection, OptionalExtension};
use std::num::NonZeroU32;

use zcash_client_backend::{
    data_api::{
        Account as _, AccountBirthday, AccountPurpose, CommitmentTreeMaintenance, WalletRead,
        WalletWrite,
        anchor_retention::AnchorRetentionInterval,
        chain::{CompactChainState, error::Error as ScanDbError},
        scanning::ScanPriority,
        testing::{AddressType, TestBuilder, pool::ShieldedPoolTester, sapling::SaplingPoolTester},
    },
    scanning::ScanError,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    consensus::{BlockHeight, NetworkUpgrade, Parameters as _},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};

use crate::testing::{BlockCache, db::TestDbFactory};

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// Shard and checkpoint rows a scan would write. The initializer may already have stored an
/// empty cap; that row is compared separately so a view-only scan can be shown not to touch it.
fn shard_and_checkpoint_rows(conn: &Connection) -> i64 {
    let sapling = count(conn, "SELECT COUNT(*) FROM sapling_tree_shards")
        + count(conn, "SELECT COUNT(*) FROM sapling_tree_checkpoints");
    #[cfg(feature = "orchard")]
    let other = count(conn, "SELECT COUNT(*) FROM orchard_tree_shards")
        + count(conn, "SELECT COUNT(*) FROM orchard_tree_checkpoints")
        + count(conn, "SELECT COUNT(*) FROM ironwood_tree_shards")
        + count(conn, "SELECT COUNT(*) FROM ironwood_tree_checkpoints");
    #[cfg(not(feature = "orchard"))]
    let other = 0;
    sapling + other
}

fn cap_blobs(conn: &Connection) -> Vec<Option<Vec<u8>>> {
    fn one(conn: &Connection, table: &str) -> Option<Vec<u8>> {
        conn.query_row(&format!("SELECT cap_data FROM {table}"), [], |row| {
            row.get(0)
        })
        .optional()
        .unwrap()
    }
    #[cfg(not(feature = "orchard"))]
    {
        vec![one(conn, "sapling_tree_cap")]
    }
    #[cfg(feature = "orchard")]
    {
        vec![
            one(conn, "sapling_tree_cap"),
            one(conn, "orchard_tree_cap"),
            one(conn, "ironwood_tree_cap"),
        ]
    }
}

fn received_notes(conn: &Connection) -> i64 {
    count(conn, "SELECT COUNT(*) FROM sapling_received_notes")
}

fn queue_priorities(conn: &Connection) -> Vec<ScanPriority> {
    conn.prepare("SELECT priority FROM scan_queue ORDER BY block_range_start")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .map(|code| super::scanning::parse_priority_code(code.unwrap()).unwrap())
        .collect()
}

fn compact_prior(
    height: BlockHeight,
    hash: BlockHash,
    sapling_tree_size: u32,
) -> CompactChainState {
    CompactChainState::from_parts(
        height,
        hash,
        sapling_tree_size,
        #[cfg(feature = "orchard")]
        0,
        #[cfg(feature = "orchard")]
        0,
    )
}

/// A spending wallet still writes note commitment tree state for a scanned note.
#[test]
fn spending_scan_writes_commitment_trees() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    assert!(st.wallet().maintains_note_commitment_trees().unwrap());

    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks(height, 1);

    let conn = st.wallet().conn();
    assert_eq!(received_notes(conn), 1);
    assert!(shard_and_checkpoint_rows(conn) > 0);
    assert_eq!(count(conn, "SELECT COUNT(*) FROM blocks"), 1);
}

/// An explicit wallet-level switch skips trees even though the account can spend.
#[test]
fn explicit_view_only_scan_skips_commitment_trees() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    st.wallet_mut()
        .db_mut()
        .set_commitment_tree_maintenance(CommitmentTreeMaintenance::ViewOnly);
    assert!(!st.wallet().maintains_note_commitment_trees().unwrap());
    let caps_before = cap_blobs(st.wallet().conn());

    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks(height, 1);

    let conn = st.wallet().conn();
    assert_eq!(received_notes(conn), 1);
    assert_eq!(
        count(
            conn,
            "SELECT COUNT(*) FROM sapling_received_notes WHERE nf IS NOT NULL"
        ),
        1
    );
    assert_eq!(
        count(
            conn,
            "SELECT COUNT(*) FROM sapling_received_notes WHERE witness_stabilized != 0"
        ),
        0
    );
    assert_eq!(shard_and_checkpoint_rows(conn), 0);
    assert_eq!(cap_blobs(conn), caps_before);
    assert_eq!(count(conn, "SELECT COUNT(*) FROM blocks"), 1);
    let stored_hash: Vec<u8> = conn
        .query_row(
            "SELECT hash FROM blocks WHERE height = ?1",
            [u32::from(height)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_hash.len(), 32);
}

/// Every account being view-only is enough; the explicit switch is not required.
#[test]
fn all_view_only_accounts_skip_commitment_trees() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let (account_id, ufvk, fvk) = {
        let account = st.test_account().unwrap();
        let ufvk = account.ufvk().unwrap().clone();
        let fvk = SaplingPoolTester::sk_to_fvk(SaplingPoolTester::usk_to_sk(account.usk()));
        (account.id(), ufvk, fvk)
    };
    let prior_hash = BlockHash([0; 32]);
    let activation = st
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    st.wallet_mut().delete_account(account_id).unwrap();
    let birthday = AccountBirthday::from_viewing_parts(activation - 1, prior_hash, None);
    assert_eq!(birthday.height(), activation);
    assert_eq!(birthday.sapling_frontier().tree_size(), 0);

    let imported = st
        .wallet_mut()
        .import_account_ufvk("view", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
        .unwrap();
    assert_matches!(imported.purpose(), AccountPurpose::ViewOnly);
    assert!(!st.wallet().maintains_note_commitment_trees().unwrap());
    let caps_before = cap_blobs(st.wallet().conn());

    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );

    // Continuity is the prior block's height, hash, and tree sizes, not a frontier.
    let prior = compact_prior(activation - 1, prior_hash, 0);
    st.try_scan_cached_blocks_from(height, &prior, 1).unwrap();

    let conn = st.wallet().conn();
    assert_eq!(received_notes(conn), 1);
    assert_eq!(shard_and_checkpoint_rows(conn), 0);
    assert_eq!(cap_blobs(conn), caps_before);
}

/// A view-only birthday may sit below Sapling activation, where no treestate exists.
#[test]
fn view_only_birthday_before_sapling_activation() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .build();

    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        st.network(),
        &[0x11; 32],
        zip32::AccountId::try_from(0).unwrap(),
    )
    .unwrap();
    let ufvk = usk.to_unified_full_viewing_key();
    let birthday =
        AccountBirthday::from_viewing_parts(BlockHeight::from_u32(0), BlockHash([7; 32]), None);
    assert_eq!(birthday.height(), BlockHeight::from_u32(1));
    assert_eq!(
        birthday.prior_chain_state().block_hash(),
        BlockHash([7; 32])
    );

    st.wallet_mut()
        .import_account_ufvk("early", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
        .unwrap();
    assert_eq!(
        st.wallet().get_wallet_birthday().unwrap(),
        Some(BlockHeight::from_u32(1))
    );
    assert!(!st.wallet().maintains_note_commitment_trees().unwrap());
}

#[test]
fn view_only_scan_rejects_prev_hash_and_tree_size_mismatch() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    st.wallet_mut()
        .db_mut()
        .set_commitment_tree_maintenance(CommitmentTreeMaintenance::ViewOnly);

    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    let activation = st
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();

    let wrong_hash = compact_prior(activation - 1, BlockHash([9; 32]), 0);
    assert_matches!(
        st.try_scan_cached_blocks_from(height, &wrong_hash, 1),
        Err(ScanDbError::Scan(ScanError::PrevHashMismatch { .. }))
    );

    let wrong_size = compact_prior(activation - 1, BlockHash([0; 32]), 50);
    assert_matches!(
        st.try_scan_cached_blocks_from(height, &wrong_size, 1),
        Err(ScanDbError::Scan(ScanError::TreeSizeMismatch { .. }))
    );

    // The failed scans persisted nothing.
    let conn = st.wallet().conn();
    assert_eq!(received_notes(conn), 0);
    assert_eq!(count(conn, "SELECT COUNT(*) FROM blocks"), 0);
    assert_eq!(shard_and_checkpoint_rows(conn), 0);
}

/// A spending wallet cannot scan from compact metadata that has no frontiers.
#[test]
fn spending_scan_requires_commitment_frontiers() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    let activation = st
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    let prior = compact_prior(activation - 1, BlockHash([0; 32]), 0);
    assert_matches!(
        st.try_scan_cached_blocks_from(height, &prior, 1),
        Err(ScanDbError::Scan(ScanError::CommitmentTreeRequired { .. }))
    );
}

/// A shard end beyond the scanned block is what makes a spending scan insert `FoundNote`.
/// View-only marks the scanned block `Scanned` and does not.
#[test]
fn view_only_scan_does_not_extend_found_note_ranges() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    st.wallet_mut()
        .db_mut()
        .set_commitment_tree_maintenance(CommitmentTreeMaintenance::ViewOnly);

    let activation = st
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO sapling_tree_shards (shard_index, subtree_end_height) VALUES (0, ?1)",
            [u32::from(activation + 1000)],
        )
        .unwrap();

    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks(height, 1);

    let priorities = queue_priorities(st.wallet().conn());
    assert!(
        priorities.contains(&ScanPriority::Scanned),
        "scanned range missing from {priorities:?}"
    );
    assert!(
        !priorities.contains(&ScanPriority::FoundNote),
        "view-only queue inserted FoundNote: {priorities:?}"
    );
}

#[test]
fn view_only_chain_tip_does_not_walk_back_to_an_incomplete_shard() {
    let mut spending = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let mut view_only = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    view_only
        .wallet_mut()
        .db_mut()
        .set_commitment_tree_maintenance(CommitmentTreeMaintenance::ViewOnly);

    let activation = spending
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    let mut tables = vec!["sapling_tree_shards"];
    #[cfg(feature = "orchard")]
    {
        tables.push("orchard_tree_shards");
        tables.push("ironwood_tree_shards");
    }
    for wallet in [spending.wallet().conn(), view_only.wallet().conn()] {
        for table in &tables {
            wallet
                .execute(
                    &format!(
                        "INSERT INTO {table} (shard_index, subtree_end_height) VALUES (0, ?1)"
                    ),
                    [u32::from(activation)],
                )
                .unwrap();
        }
    }

    let tip = activation + 400;
    spending.wallet_mut().update_chain_tip(tip).unwrap();
    view_only.wallet_mut().update_chain_tip(tip).unwrap();

    let spending_priorities = queue_priorities(spending.wallet().conn());
    let view_priorities = queue_priorities(view_only.wallet().conn());
    assert!(
        spending_priorities.contains(&ScanPriority::ChainTip),
        "spending tip queue: {spending_priorities:?}"
    );
    assert!(
        !view_priorities.contains(&ScanPriority::ChainTip),
        "view-only tip queue: {view_priorities:?}"
    );
    assert!(
        view_priorities.contains(&ScanPriority::Historic),
        "view-only tip queue: {view_priorities:?}"
    );
}

#[test]
fn view_only_chain_tip_keeps_verify_lookahead() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    st.wallet_mut()
        .db_mut()
        .set_commitment_tree_maintenance(CommitmentTreeMaintenance::ViewOnly);

    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks(height, 1);
    // Far enough above the scanned block that the scanned height is inside the stable region,
    // so the lookahead is `Verify` and the rest of the catch-up is `Historic`.
    st.wallet_mut().update_chain_tip(height + 200).unwrap();

    let priorities = queue_priorities(st.wallet().conn());
    assert!(
        priorities.contains(&ScanPriority::Verify),
        "view-only tip queue: {priorities:?}"
    );
    assert!(
        priorities.contains(&ScanPriority::Historic),
        "view-only tip queue: {priorities:?}"
    );
    assert!(
        !priorities.contains(&ScanPriority::ChainTip),
        "view-only tip queue: {priorities:?}"
    );
    assert!(
        !priorities.contains(&ScanPriority::FoundNote),
        "view-only tip queue: {priorities:?}"
    );
}

#[test]
fn spending_wallet_can_disable_anchor_retention() {
    let activation = BlockHeight::from_u32(100_000);
    let network = LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    };
    let interval = AnchorRetentionInterval::custom(NonZeroU32::new(1).unwrap());

    let scan_one = |retain: bool| {
        let mut st = TestBuilder::new()
            .with_network(network)
            .with_anchor_retention_interval(interval)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        st.wallet_mut()
            .db_mut()
            .set_anchor_retention_enabled(retain);
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let (height, _, _) = st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(100_000),
        );
        st.scan_cached_blocks(height, 1);
        count(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM sapling_tree_retained_checkpoints",
        )
    };

    assert!(
        scan_one(true) > 0,
        "a one-block anchor grid retains the scanned checkpoint"
    );
    assert_eq!(
        scan_one(false),
        0,
        "disabling anchor retention stores no durable anchor"
    );
}
