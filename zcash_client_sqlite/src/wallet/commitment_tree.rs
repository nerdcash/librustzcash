//! SQLite-backed implementation of [`ShardStore`] for note commitment trees.

use rusqlite::{self, OptionalExtension, named_params};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    error, fmt,
    io::{self, Cursor},
    marker::PhantomData,
    num::NonZeroU32,
    ops::Range,
    rc::Rc,
    sync::Arc,
};

use incrementalmerkletree::{Address, Hashable, Level, Position, Retention};
use shardtree::{
    LocatedPrunableTree, LocatedTree, PrunableTree, RetentionFlags,
    error::{QueryError, ShardTreeError},
    store::{Checkpoint, ShardStore, TreeState},
};

use zcash_client_backend::{
    data_api::{chain::CommitmentTreeRoot, wallet::TargetHeight},
    serialization::shardtree::{read_shard, write_shard},
};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight},
};

use crate::{error::SqliteClientError, sapling_tree};

#[cfg(feature = "orchard")]
use {
    crate::{IRONWOOD_TABLES_PREFIX, ORCHARD_TABLES_PREFIX, ironwood_tree, orchard_tree},
    incrementalmerkletree::Marking,
    shardtree::{ShardTree, store::memory::MemoryShardStore},
    zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
};

use super::common::{TableConstants, table_constants};

/// Errors that can appear in SQLite-back [`ShardStore`] implementation operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Errors in deserializing stored shard data
    Serialization(io::Error),
    /// Errors encountered querying stored shard data
    Query(rusqlite::Error),
    /// Raised when the caller attempts to add a checkpoint at a block height where a checkpoint
    /// already exists, but the tree state being checkpointed or the marks removed at that
    /// checkpoint conflict with the existing tree state.
    CheckpointConflict {
        /// The block height of the conflicting checkpoint.
        checkpoint_id: BlockHeight,
        /// The checkpoint data that was attempted to be inserted.
        checkpoint: Checkpoint,
        /// The tree state already stored at that checkpoint height.
        extant_tree_state: TreeState,
        /// The marks-removed set already stored at that checkpoint height, if any.
        extant_marks_removed: Option<BTreeSet<Position>>,
    },
    /// Raised when attempting to add shard roots to the database that
    /// are discontinuous with the existing roots in the database.
    SubtreeDiscontinuity {
        /// The index range of the subtree roots that were attempted to be inserted.
        attempted_insertion_range: Range<u64>,
        /// The index range of subtree roots already present in the database.
        existing_range: Range<u64>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::Serialization(err) => write!(f, "Commitment tree serialization error: {err}"),
            Error::Query(err) => write!(f, "Commitment tree query or update error: {err}"),
            Error::CheckpointConflict {
                checkpoint_id,
                checkpoint,
                extant_tree_state,
                extant_marks_removed,
            } => {
                write!(
                    f,
                    "Conflict at checkpoint id {checkpoint_id}, tried to insert {checkpoint:?}, which is incompatible with existing state ({extant_tree_state:?}, {extant_marks_removed:?})"
                )
            }
            Error::SubtreeDiscontinuity {
                attempted_insertion_range,
                existing_range,
            } => {
                write!(
                    f,
                    "Attempted to write subtree roots with indices {attempted_insertion_range:?} which is discontinuous with existing subtree range {existing_range:?}",
                )
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::Serialization(e) => Some(e),
            Error::Query(e) => Some(e),
            Error::CheckpointConflict { .. } => None,
            Error::SubtreeDiscontinuity { .. } => None,
        }
    }
}

/// An implementation of [`ShardStore`] backed by an SQLite database.
///
/// When [`Self::enable_write_back`] is used, shard and checkpoint mutations stay
/// in memory until [`Self::flush_write_back`] or the store is dropped. Reads of shards
/// that have not been modified are served from SQLite and are not rewritten, so a flush
/// persists the same rows an immediate store would have left.
pub struct SqliteShardStore<C, H, const SHARD_HEIGHT: u8> {
    pub(crate) conn: C,
    table_prefix: &'static str,
    _hash_type: PhantomData<H>,
    write_back: Option<RefCell<ShardWriteBack<H>>>,
    /// Receives a flush error from [`Drop`] when the caller cannot flush explicitly.
    flush_report: Option<Rc<RefCell<Result<(), Error>>>>,
}

impl<C, H, const SHARD_HEIGHT: u8> SqliteShardStore<C, H, SHARD_HEIGHT> {
    const SHARD_ROOT_LEVEL: Level = Level::new(SHARD_HEIGHT);

    pub(crate) fn from_connection(
        conn: C,
        table_prefix: &'static str,
    ) -> Result<Self, rusqlite::Error> {
        Ok(SqliteShardStore {
            conn,
            table_prefix,
            _hash_type: PhantomData,
            write_back: None,
            flush_report: None,
        })
    }
}

/// In-memory overlay for one note-commitment tree update.
///
/// Shards stay on disk until a read or a write touches them. Checkpoints, the cap, and the
/// retained-checkpoint set are small and are loaded up front so pruning and anchor retention see
/// the same state the immediate store would. A flush writes only the rows that actually changed,
/// through the same SQL helpers the immediate store uses.
struct ShardWriteBack<H> {
    /// `None` means a read proved the shard is absent. A later [`ShardStore::put_shard`] replaces
    /// that with `Some`.
    shards: BTreeMap<u64, Option<LocatedPrunableTree<H>>>,
    dirty_shards: BTreeSet<u64>,
    /// SQL rows at or above this index are deleted on flush. A shard inserted after the truncate
    /// is still visible from `shards` and is not hidden by this watermark.
    truncate_from: Option<u64>,
    cap: PrunableTree<H>,
    cap_dirty: bool,
    checkpoints: BTreeMap<BlockHeight, Checkpoint>,
    /// Checkpoint ids that existed in SQLite when the cache was enabled.
    loaded_ids: BTreeSet<BlockHeight>,
    dirty_checkpoints: BTreeSet<BlockHeight>,
    removed_checkpoints: BTreeSet<BlockHeight>,
    retained: BTreeSet<BlockHeight>,
    initial_retained: BTreeSet<BlockHeight>,
}

/// Sort key matching `ORDER BY position` (NULLs first) with `checkpoint_id` as the tie break.
///
/// `checkpoint_id` is the integer primary key, so it is the rowid. Within one batch, new
/// checkpoints are inserted in id order and an update reinserts the same id, so this matches the
/// rowid order SQLite uses when positions tie.
fn checkpoint_order(id: BlockHeight, checkpoint: &Checkpoint) -> (u8, u64, u32) {
    match checkpoint.tree_state() {
        TreeState::Empty => (0, 0, u32::from(id)),
        TreeState::AtPosition(position) => (1, u64::from(position), u32::from(id)),
    }
}

impl<H: HashSer + Clone> ShardWriteBack<H> {
    fn load(conn: &rusqlite::Transaction<'_>, table_prefix: &'static str) -> Result<Self, Error> {
        let _span = tracing::info_span!("commitment_load_cache", table_prefix).entered();
        let cap = get_cap(conn, table_prefix)?;
        let mut checkpoints = BTreeMap::new();
        let count = checkpoint_count(conn, table_prefix)?;
        with_checkpoints(conn, table_prefix, count, |id, checkpoint| {
            checkpoints.insert(*id, checkpoint.clone());
            Ok(())
        })?;
        let loaded_ids = checkpoints.keys().copied().collect();
        let retained = retained_checkpoints(conn, table_prefix)?;
        Ok(Self {
            shards: BTreeMap::new(),
            dirty_shards: BTreeSet::new(),
            truncate_from: None,
            cap,
            cap_dirty: false,
            checkpoints,
            loaded_ids,
            dirty_checkpoints: BTreeSet::new(),
            removed_checkpoints: BTreeSet::new(),
            retained: retained.clone(),
            initial_retained: retained,
        })
    }

    fn get_shard(
        &mut self,
        conn: &rusqlite::Connection,
        table_prefix: &'static str,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<H>>, Error> {
        let index = shard_root.index();
        if let Some(hit) = self.shards.get(&index) {
            return Ok(hit.clone());
        }
        if self.truncate_from.is_some_and(|from| index >= from) {
            self.shards.insert(index, None);
            return Ok(None);
        }
        let loaded = get_shard(conn, table_prefix, shard_root)?;
        self.shards.insert(index, loaded.clone());
        Ok(loaded)
    }

    fn shard_roots(
        &self,
        conn: &rusqlite::Connection,
        table_prefix: &'static str,
        shard_root_level: Level,
    ) -> Result<Vec<Address>, Error> {
        let mut indexes = get_shard_roots(conn, table_prefix, shard_root_level)?
            .into_iter()
            .map(|addr| addr.index())
            .filter(|index| self.truncate_from.is_none_or(|from| *index < from))
            .collect::<BTreeSet<_>>();
        for (index, shard) in &self.shards {
            if shard.is_some() {
                indexes.insert(*index);
            } else {
                indexes.remove(index);
            }
        }
        Ok(indexes
            .into_iter()
            .map(|index| Address::from_parts(shard_root_level, index))
            .collect())
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<H>) {
        let index = subtree.root_addr().index();
        self.shards.insert(index, Some(subtree));
        self.dirty_shards.insert(index);
    }

    fn truncate_shards(&mut self, shard_index: u64) {
        self.shards.split_off(&shard_index);
        self.dirty_shards.retain(|index| *index < shard_index);
        self.truncate_from = Some(
            self.truncate_from
                .map_or(shard_index, |from| from.min(shard_index)),
        );
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: BlockHeight,
        checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        if let Some(extant) = self.checkpoints.get(&checkpoint_id) {
            if extant.tree_state() != checkpoint.tree_state() {
                return Err(Error::CheckpointConflict {
                    checkpoint_id,
                    checkpoint,
                    extant_tree_state: extant.tree_state(),
                    extant_marks_removed: None,
                });
            }
            if extant.marks_removed() != checkpoint.marks_removed() {
                return Err(Error::CheckpointConflict {
                    checkpoint_id,
                    checkpoint,
                    extant_tree_state: extant.tree_state(),
                    extant_marks_removed: Some(extant.marks_removed().clone()),
                });
            }
            return Ok(());
        }
        self.removed_checkpoints.remove(&checkpoint_id);
        self.checkpoints.insert(checkpoint_id, checkpoint);
        self.dirty_checkpoints.insert(checkpoint_id);
        Ok(())
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: BlockHeight,
        update: F,
    ) -> Result<bool, Error>
    where
        F: FnOnce(&mut Checkpoint) -> Result<(), Error>,
    {
        let Some(mut checkpoint) = self.checkpoints.get(&checkpoint_id).cloned() else {
            return Ok(false);
        };
        update(&mut checkpoint)?;
        self.removed_checkpoints.remove(&checkpoint_id);
        self.checkpoints.insert(checkpoint_id, checkpoint);
        self.dirty_checkpoints.insert(checkpoint_id);
        Ok(true)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: BlockHeight) {
        if self.checkpoints.remove(&checkpoint_id).is_some() {
            self.dirty_checkpoints.remove(&checkpoint_id);
            if self.loaded_ids.contains(&checkpoint_id) {
                self.removed_checkpoints.insert(checkpoint_id);
            }
        }
    }

    fn truncate_checkpoints_retaining(&mut self, checkpoint_id: BlockHeight) {
        let mut higher = self.checkpoints.split_off(&checkpoint_id);
        if let Some(kept) = higher.remove(&checkpoint_id) {
            if kept.marks_removed().is_empty() {
                self.checkpoints.insert(checkpoint_id, kept);
            } else {
                self.checkpoints.insert(
                    checkpoint_id,
                    Checkpoint::from_parts(kept.tree_state(), BTreeSet::new()),
                );
                self.dirty_checkpoints.insert(checkpoint_id);
                self.removed_checkpoints.remove(&checkpoint_id);
            }
        }
        for (id, _) in higher {
            self.dirty_checkpoints.remove(&id);
            if self.loaded_ids.contains(&id) {
                self.removed_checkpoints.insert(id);
            }
        }
    }

    fn checkpoints_in_position_order(&self, limit: usize) -> Vec<(BlockHeight, Checkpoint)> {
        let mut pairs = self
            .checkpoints
            .iter()
            .map(|(id, checkpoint)| (*id, checkpoint.clone()))
            .collect::<Vec<_>>();
        pairs.sort_by_key(|(id, checkpoint)| checkpoint_order(*id, checkpoint));
        pairs.truncate(limit);
        pairs
    }

    fn flush(
        self,
        conn: &rusqlite::Transaction<'_>,
        table_prefix: &'static str,
    ) -> Result<(), Error> {
        tracing::debug!(
            shards = self.dirty_shards.len(),
            truncate = self.truncate_from.is_some(),
            checkpoints = self.dirty_checkpoints.len(),
            removed_checkpoints = self.removed_checkpoints.len(),
            cap = self.cap_dirty,
            "flushing commitment tree write-back cache"
        );

        if let Some(index) = self.truncate_from {
            let _span = tracing::info_span!("commitment_flush_truncate").entered();
            truncate_shards(conn, table_prefix, index)?;
        }
        {
            let _span =
                tracing::info_span!("commitment_flush_shards", shards = self.dirty_shards.len())
                    .entered();
            for index in &self.dirty_shards {
                if let Some(Some(shard)) = self.shards.get(index) {
                    put_shard(conn, table_prefix, shard.clone())?;
                }
            }
        }
        if self.cap_dirty {
            let _span = tracing::info_span!("commitment_flush_cap").entered();
            put_cap(conn, table_prefix, self.cap)?;
        }
        {
            let _span = tracing::info_span!(
                "commitment_flush_checkpoints",
                removed = self.removed_checkpoints.len(),
                dirty = self.dirty_checkpoints.len()
            )
            .entered();
            for id in &self.removed_checkpoints {
                remove_checkpoint(conn, table_prefix, *id)?;
            }
            let mut dirty_ids = self.dirty_checkpoints.iter().copied().collect::<Vec<_>>();
            dirty_ids.sort();
            for id in dirty_ids {
                if self.removed_checkpoints.contains(&id) {
                    continue;
                }
                let Some(checkpoint) = self.checkpoints.get(&id).cloned() else {
                    continue;
                };
                // An id that already has a row cannot be inserted again when its marks changed:
                // `add_checkpoint` treats that as a conflict. Delete the old row first. The id is the
                // primary key, so the replacement keeps the same rowid.
                if self.loaded_ids.contains(&id) {
                    remove_checkpoint(conn, table_prefix, id)?;
                }
                add_checkpoint(conn, table_prefix, id, checkpoint)?;
            }
        }
        for id in self.initial_retained.difference(&self.retained) {
            remove_retained_checkpoint(conn, table_prefix, *id)?;
        }
        for id in self.retained.difference(&self.initial_retained) {
            add_retained_checkpoint(conn, table_prefix, *id)?;
        }
        Ok(())
    }
}

impl<'conn, 'a: 'conn, H: HashSer + Clone, const SHARD_HEIGHT: u8>
    SqliteShardStore<&'a rusqlite::Transaction<'conn>, H, SHARD_HEIGHT>
{
    /// Start serving this store from memory.
    ///
    /// Reads of shards that this batch does not touch still come from SQLite. Calling this twice
    /// keeps the cache already in use. [`Self::flush_write_back`] writes the changes and returns
    /// the store to immediate mode.
    pub(crate) fn enable_write_back(&mut self) -> Result<(), Error> {
        if self.write_back.is_some() {
            return Ok(());
        }
        self.write_back = Some(RefCell::new(ShardWriteBack::load(
            self.conn,
            self.table_prefix,
        )?));
        Ok(())
    }

    /// Where a [`WriteBackOnDrop`] guard should record a flush failure.
    pub(crate) fn set_flush_report(&mut self, report: Rc<RefCell<Result<(), Error>>>) {
        self.flush_report = Some(report);
    }

    /// Flush this cache when the returned guard drops.
    ///
    /// The guard holds no borrow, so a tree callback can run while it is alive. Drop it after the
    /// callback returns and before committing.
    pub(crate) fn flush_on_drop(&mut self) -> WriteBackOnDrop<'conn, 'a, H, SHARD_HEIGHT> {
        WriteBackOnDrop { store: self }
    }

    /// Persist cached changes and disable the cache.
    ///
    /// A second call is a no-op. On error the caller must roll back the transaction: a partial
    /// flush is not a consistent tree, and the cache has been dropped.
    pub(crate) fn flush_write_back(&mut self) -> Result<(), Error> {
        let Some(cache) = self.write_back.take() else {
            return Ok(());
        };
        cache.into_inner().flush(self.conn, self.table_prefix)
    }
}

/// Flushes a transaction-backed [`SqliteShardStore`] when dropped.
///
/// `WalletCommitmentTrees` callbacks borrow the tree for a lifetime that the borrow checker will
/// not treat as finished until the callback's result is no longer in scope. This guard flushes
/// through a pointer so that flush does not need a second borrow of the tree.
pub(crate) struct WriteBackOnDrop<'conn, 'a: 'conn, H: HashSer + Clone, const SHARD_HEIGHT: u8> {
    store: *mut SqliteShardStore<&'a rusqlite::Transaction<'conn>, H, SHARD_HEIGHT>,
}

impl<'conn, 'a: 'conn, H: HashSer + Clone, const SHARD_HEIGHT: u8> Drop
    for WriteBackOnDrop<'conn, 'a, H, SHARD_HEIGHT>
{
    fn drop(&mut self) {
        if self.store.is_null() {
            return;
        }
        // SAFETY: `flush_on_drop` borrows the store just long enough to take this pointer, and the
        // caller keeps the store alive until this guard drops. The guard is dropped only after the
        // tree callback has returned, so nothing else holds a reference to the store.
        let store = unsafe { &mut *self.store };
        if store.write_back.is_none() {
            return;
        }
        let flushed = store.flush_write_back();
        if let (Some(report), Err(err)) = (&store.flush_report, flushed) {
            *report.borrow_mut() = Err(err);
        }
    }
}

impl<'conn, 'a: 'conn, H: HashSer + Clone, const SHARD_HEIGHT: u8> ShardStore
    for SqliteShardStore<&'a rusqlite::Transaction<'conn>, H, SHARD_HEIGHT>
{
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = Error;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return cache
                .borrow_mut()
                .get_shard(self.conn, self.table_prefix, shard_root);
        }
        get_shard(self.conn, self.table_prefix, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        let Some(cache) = &self.write_back else {
            return last_shard(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL);
        };
        let roots =
            cache
                .borrow()
                .shard_roots(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)?;
        let Some(addr) = roots.last().copied() else {
            return Ok(None);
        };
        if let Some(hit) = cache.borrow().shards.get(&addr.index()) {
            return Ok(hit.clone());
        }
        // `last_shard` reads `shard_data` only. `get_shard` also overlays `root_hash`, and the
        // tree appends to whatever `last_shard` returned, so a cache miss must match that read.
        // A truncate can hide a higher on-disk shard, which the SQL helper would still return.
        if cache.borrow().truncate_from.is_some() {
            read_shard_data(self.conn, self.table_prefix, addr)
        } else {
            last_shard(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
        }
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            cache.borrow_mut().put_shard(subtree);
            return Ok(());
        }
        put_shard(self.conn, self.table_prefix, subtree)
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return cache.borrow().shard_roots(
                self.conn,
                self.table_prefix,
                Self::SHARD_ROOT_LEVEL,
            );
        }
        get_shard_roots(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            cache.borrow_mut().truncate_shards(shard_index);
            return Ok(());
        }
        truncate_shards(self.conn, self.table_prefix, shard_index)
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache.borrow().cap.clone());
        }
        get_cap(self.conn, self.table_prefix)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            let mut cache = cache.borrow_mut();
            cache.cap = cap;
            cache.cap_dirty = true;
            return Ok(());
        }
        put_cap(self.conn, self.table_prefix, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache.borrow().checkpoints.keys().next().copied());
        }
        min_checkpoint_id(self.conn, self.table_prefix)
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache.borrow().checkpoints.keys().next_back().copied());
        }
        max_checkpoint_id(self.conn, self.table_prefix)
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            return cache.borrow_mut().add_checkpoint(checkpoint_id, checkpoint);
        }
        add_checkpoint(self.conn, self.table_prefix, checkpoint_id, checkpoint)
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache.borrow().checkpoints.len());
        }
        checkpoint_count(self.conn, self.table_prefix)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache
                .borrow()
                .checkpoints
                .iter()
                .rev()
                .nth(checkpoint_depth)
                .map(|(id, checkpoint)| (*id, checkpoint.clone())));
        }
        get_checkpoint_at_depth(self.conn, self.table_prefix, checkpoint_depth)
            .map_err(Error::Query)
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache.borrow().checkpoints.get(checkpoint_id).cloned());
        }
        get_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        if let Some(cache) = &self.write_back {
            // Snapshot first. Pruning calls back into the store, and the callback must not run
            // while the cache `RefCell` is borrowed.
            let pairs = cache.borrow().checkpoints_in_position_order(limit);
            for (id, checkpoint) in &pairs {
                callback(id, checkpoint)?;
            }
            return Ok(());
        }
        with_checkpoints(self.conn, self.table_prefix, limit, callback)
    }

    fn for_each_checkpoint<F>(&self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        if let Some(cache) = &self.write_back {
            let pairs = cache.borrow().checkpoints_in_position_order(limit);
            for (id, checkpoint) in &pairs {
                callback(id, checkpoint)?;
            }
            return Ok(());
        }
        with_checkpoints(self.conn, self.table_prefix, limit, callback)
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        if let Some(cache) = &self.write_back {
            // Apply `update` to a copy before publishing it, matching the SQL helper. The copy is
            // updated outside the `RefCell` borrow so a callback that re-enters the store cannot
            // deadlock on it.
            let mut checkpoint = {
                let borrowed = cache.borrow();
                let Some(checkpoint) = borrowed.checkpoints.get(checkpoint_id).cloned() else {
                    return Ok(false);
                };
                checkpoint
            };
            update(&mut checkpoint)?;
            return cache
                .borrow_mut()
                .update_checkpoint_with(*checkpoint_id, |slot| {
                    *slot = checkpoint;
                    Ok(())
                });
        }
        update_checkpoint_with(self.conn, self.table_prefix, *checkpoint_id, update)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            cache.borrow_mut().remove_checkpoint(*checkpoint_id);
            return Ok(());
        }
        remove_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn add_retained_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            cache.borrow_mut().retained.insert(checkpoint_id);
            return Ok(());
        }
        add_retained_checkpoint(self.conn, self.table_prefix, checkpoint_id)
    }

    fn remove_retained_checkpoint(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            cache.borrow_mut().retained.remove(checkpoint_id);
            return Ok(());
        }
        remove_retained_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn retained_checkpoints(&self) -> Result<BTreeSet<Self::CheckpointId>, Self::Error> {
        if let Some(cache) = &self.write_back {
            return Ok(cache.borrow().retained.clone());
        }
        retained_checkpoints(self.conn, self.table_prefix)
    }

    fn truncate_checkpoints_retaining(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        if let Some(cache) = &self.write_back {
            cache
                .borrow_mut()
                .truncate_checkpoints_retaining(*checkpoint_id);
            return Ok(());
        }
        truncate_checkpoints_retaining(self.conn, self.table_prefix, *checkpoint_id)
    }
}

impl<H: HashSer, const SHARD_HEIGHT: u8> ShardStore
    for SqliteShardStore<rusqlite::Connection, H, SHARD_HEIGHT>
{
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = Error;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        get_shard(&self.conn, self.table_prefix, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        last_shard(&self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        put_shard(&tx, self.table_prefix, subtree)?;
        tx.commit().map_err(Error::Query)?;
        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        get_shard_roots(&self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Self::Error> {
        truncate_shards(&self.conn, self.table_prefix, shard_index)
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        get_cap(&self.conn, self.table_prefix)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_cap(&self.conn, self.table_prefix, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        min_checkpoint_id(&self.conn, self.table_prefix)
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        max_checkpoint_id(&self.conn, self.table_prefix)
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        add_checkpoint(&tx, self.table_prefix, checkpoint_id, checkpoint)?;
        tx.commit().map_err(Error::Query)
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        checkpoint_count(&self.conn, self.table_prefix)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        get_checkpoint_at_depth(&self.conn, self.table_prefix, checkpoint_depth)
            .map_err(Error::Query)
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        get_checkpoint(&self.conn, self.table_prefix, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        with_checkpoints(&tx, self.table_prefix, limit, callback)?;
        tx.commit().map_err(Error::Query)
    }

    fn for_each_checkpoint<F>(&self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.unchecked_transaction().map_err(Error::Query)?;
        with_checkpoints(&tx, self.table_prefix, limit, callback)?;
        // Here, we use `tx.rollback` as the semantics of this method is that the callback must
        // not mutate the data store.
        tx.rollback().map_err(Error::Query)
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        let result = update_checkpoint_with(&tx, self.table_prefix, *checkpoint_id, update)?;
        tx.commit().map_err(Error::Query)?;
        Ok(result)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        remove_checkpoint(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Error::Query)
    }

    fn add_retained_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        add_retained_checkpoint(&tx, self.table_prefix, checkpoint_id)?;
        tx.commit().map_err(Error::Query)
    }

    fn remove_retained_checkpoint(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        remove_retained_checkpoint(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Error::Query)
    }

    fn retained_checkpoints(&self) -> Result<BTreeSet<Self::CheckpointId>, Self::Error> {
        retained_checkpoints(&self.conn, self.table_prefix)
    }

    fn truncate_checkpoints_retaining(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        truncate_checkpoints_retaining(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Error::Query)
    }
}

/// Returns the stored root hash of the completed subtree with the given index, as most
/// recently written by [`put_shard_roots`] or recorded by [`put_shard`], or `Ok(None)` if
/// no row exists for the subtree or its `root_hash` is unknown.
pub(crate) fn get_subtree_root<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    index: u64,
) -> Result<Option<H>, Error> {
    conn.query_row(
        &format!(
            "SELECT root_hash
             FROM {table_prefix}_tree_shards
             WHERE shard_index = :shard_index"
        ),
        named_params![":shard_index": index],
        |row| row.get::<_, Option<Vec<u8>>>(0),
    )
    .optional()
    .map_err(Error::Query)?
    .flatten()
    .map(|bytes| H::read(Cursor::new(bytes)).map_err(Error::Serialization))
    .transpose()
}

pub(crate) fn get_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_addr: Address,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_data, root_hash
             FROM {table_prefix}_tree_shards
             WHERE shard_index = :shard_index"
        ),
        named_params![":shard_index": shard_root_addr.index()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
    )
    .optional()
    .map_err(Error::Query)?
    .map(|(shard_data, root_hash)| {
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        let located_tree =
            LocatedPrunableTree::from_parts(shard_root_addr, shard_tree).map_err(|e| {
                Error::Serialization(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Tree contained invalid data at address {e:?}"),
                ))
            })?;
        if let Some(root_hash_data) = root_hash {
            let root_hash = H::read(Cursor::new(root_hash_data)).map_err(Error::Serialization)?;
            Ok(located_tree.reannotate_root(Some(Arc::new(root_hash))))
        } else {
            Ok(located_tree)
        }
    })
    .transpose()
}

/// Reads one shard the way [`last_shard`] does: `shard_data` only, with no `root_hash` overlay.
fn read_shard_data<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root: Address,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_data
             FROM {table_prefix}_tree_shards
             WHERE shard_index = :shard_index"
        ),
        named_params![":shard_index": shard_root.index()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(Error::Query)?
    .map(|shard_data| {
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        LocatedPrunableTree::from_parts(shard_root, shard_tree).map_err(|addr| {
            Error::Serialization(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Tree contained invalid data at address {addr:?}"),
            ))
        })
    })
    .transpose()
}

pub(crate) fn last_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_index, shard_data
             FROM {table_prefix}_tree_shards
             ORDER BY shard_index DESC
             LIMIT 1"
        ),
        [],
        |row| {
            let shard_index: u64 = row.get(0)?;
            let shard_data: Vec<u8> = row.get(1)?;
            Ok((shard_index, shard_data))
        },
    )
    .optional()
    .map_err(Error::Query)?
    .map(|(shard_index, shard_data)| {
        let shard_root = Address::from_parts(shard_root_level, shard_index);
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        LocatedPrunableTree::from_parts(shard_root, shard_tree).map_err(|e| {
            Error::Serialization(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Tree contained invalid data at address {e:?}"),
            ))
        })
    })
    .transpose()
}

/// Returns an error iff the proposed insertion range
/// for the tree shards would create a discontinuity
/// in the database.
#[tracing::instrument(skip(conn))]
fn check_shard_discontinuity(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    proposed_insertion_range: Range<u64>,
) -> Result<(), Error> {
    if let Ok((Some(stored_min), Some(stored_max))) = conn
        .query_row(
            &format!("SELECT MIN(shard_index), MAX(shard_index) FROM {table_prefix}_tree_shards"),
            [],
            |row| {
                let min = row.get::<_, Option<u64>>(0)?;
                let max = row.get::<_, Option<u64>>(1)?;
                Ok((min, max))
            },
        )
        .map_err(Error::Query)
    {
        // If the ranges overlap, or are directly adjacent, then we aren't creating a
        // discontinuity. We can check this by comparing their start-inclusive,
        // end-exclusive bounds:
        // - If `cur_start == ins_end` then the proposed insertion range is immediately
        //   before the current shards. If `cur_start > ins_end` then there is a gap.
        // - If `ins_start == cur_end` then the proposed insertion range is immediately
        //   after the current shards. If `ins_start > cur_end` then there is a gap.
        let (cur_start, cur_end) = (stored_min, stored_max + 1);
        let (ins_start, ins_end) = (proposed_insertion_range.start, proposed_insertion_range.end);
        if cur_start > ins_end || ins_start > cur_end {
            return Err(Error::SubtreeDiscontinuity {
                attempted_insertion_range: proposed_insertion_range,
                existing_range: cur_start..cur_end,
            });
        }
    }

    Ok(())
}

pub(crate) fn put_shard<H: HashSer>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    subtree: LocatedPrunableTree<H>,
) -> Result<(), Error> {
    let subtree_root_hash = subtree
        .root()
        .annotation()
        .and_then(|ann| {
            ann.as_ref().map(|rc| {
                let mut root_hash = vec![];
                rc.write(&mut root_hash)?;
                Ok(root_hash)
            })
        })
        .transpose()
        .map_err(Error::Serialization)?;

    let subtree_data = {
        let _span = tracing::info_span!("commitment_serialize_shard").entered();
        let mut subtree_data = vec![];
        write_shard(&mut subtree_data, subtree.root()).map_err(Error::Serialization)?;
        subtree_data
    };

    let shard_index = subtree.root_addr().index();

    {
        let _span = tracing::info_span!("commitment_shard_discontinuity").entered();
        check_shard_discontinuity(conn, table_prefix, shard_index..shard_index + 1)?;
    }

    let mut stmt_put_shard = conn
        .prepare_cached(&format!(
            "INSERT INTO {table_prefix}_tree_shards (shard_index, root_hash, shard_data)
             VALUES (:shard_index, :root_hash, :shard_data)
             ON CONFLICT (shard_index) DO UPDATE
             SET root_hash = :root_hash,
             shard_data = :shard_data"
        ))
        .map_err(Error::Query)?;

    stmt_put_shard
        .execute(named_params![
            ":shard_index": shard_index,
            ":root_hash": subtree_root_hash,
            ":shard_data": subtree_data
        ])
        .map_err(Error::Query)?;

    Ok(())
}

pub(crate) fn get_shard_roots(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Vec<Address>, Error> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT shard_index FROM {table_prefix}_tree_shards ORDER BY shard_index"
        ))
        .map_err(Error::Query)?;
    let mut rows = stmt.query([]).map_err(Error::Query)?;

    let mut res = vec![];
    while let Some(row) = rows.next().map_err(Error::Query)? {
        res.push(Address::from_parts(
            shard_root_level,
            row.get(0).map_err(Error::Query)?,
        ));
    }
    Ok(res)
}

pub(crate) fn truncate_shards(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_index: u64,
) -> Result<(), Error> {
    conn.execute(
        &format!("DELETE FROM {table_prefix}_tree_shards WHERE shard_index >= ?"),
        [shard_index],
    )
    .map_err(Error::Query)
    .map(|_| ())
}

#[tracing::instrument(skip(conn))]
pub(crate) fn get_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<PrunableTree<H>, Error> {
    conn.query_row(
        &format!("SELECT cap_data FROM {table_prefix}_tree_cap"),
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(Error::Query)?
    .map_or_else(
        || Ok(PrunableTree::empty()),
        |cap_data| read_shard(&mut Cursor::new(cap_data)).map_err(Error::Serialization),
    )
}

#[tracing::instrument(skip(conn, cap))]
pub(crate) fn put_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    cap: PrunableTree<H>,
) -> Result<(), Error> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "INSERT INTO {table_prefix}_tree_cap (cap_id, cap_data)
             VALUES (0, :cap_data)
             ON CONFLICT (cap_id) DO UPDATE
             SET cap_data = :cap_data"
        ))
        .map_err(Error::Query)?;

    let mut cap_data = vec![];
    write_shard(&mut cap_data, &cap).map_err(Error::Serialization)?;
    stmt.execute([cap_data]).map_err(Error::Query)?;

    Ok(())
}

pub(crate) fn min_checkpoint_id(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!("SELECT MIN(checkpoint_id) FROM {table_prefix}_tree_checkpoints"),
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
    .map_err(Error::Query)
}

pub(crate) fn max_checkpoint_id(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!("SELECT MAX(checkpoint_id) FROM {table_prefix}_tree_checkpoints"),
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
    .map_err(Error::Query)
}

/// Returns the lowest retained checkpoint id that is at or above `floor`, or `None`
/// if the pool's checkpoint table contains no checkpoint within `[floor, ∞)`.
pub(crate) fn min_checkpoint_id_at_or_above(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    floor: BlockHeight,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!(
            "SELECT MIN(checkpoint_id) FROM {table_prefix}_tree_checkpoints
             WHERE checkpoint_id >= :floor"
        ),
        named_params![":floor": u32::from(floor)],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
    .map_err(Error::Query)
}

/// Resets the note commitment tree with the given table prefix to contain only the roots of
/// subtrees completed at or below `truncation_height`, discarding all of its other state:
/// scanned shard contents, the cap, and all checkpoints.
///
/// This is the truncation outcome for a tree whose retained checkpoints all lie above the
/// truncation height: no checkpoint exists at or below that height for
/// `ShardTree::truncate_to_checkpoint` to target, so the tree's scanned contents postdate the
/// truncation point and must be discarded; the rescan of heights above that point re-creates
/// them. The roots of subtrees completed at or below the truncation height remain facts
/// about the retained portion of the chain, however, so they are preserved (in the form
/// fast sync would deliver them, via [`put_shard_roots`]); discarding them would leave the
/// wallet unable to construct witnesses spanning those subtrees until they had been
/// re-downloaded.
pub(crate) fn truncate_tree_to_subtree_roots<
    H: Hashable + HashSer + Clone + Eq,
    const DEPTH: u8,
    const SHARD_HEIGHT: u8,
>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    truncation_height: BlockHeight,
) -> Result<(), ShardTreeError<Error>> {
    // Collect the roots of subtrees completed at or below the truncation height. Subtree end
    // heights increase with shard index, so these form a prefix of the shard sequence;
    // re-insertion via `put_shard_roots` requires contiguity from index zero, so collection
    // stops at the first shard for which no completed root is recorded.
    let roots = {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT shard_index, subtree_end_height, root_hash
                 FROM {table_prefix}_tree_shards
                 WHERE subtree_end_height IS NOT NULL
                 AND subtree_end_height <= :truncation_height
                 AND root_hash IS NOT NULL
                 ORDER BY shard_index"
            ))
            .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;

        let rows = stmt
            .query_map(
                named_params![":truncation_height": u32::from(truncation_height)],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;

        let mut roots = vec![];
        for row in rows {
            let (shard_index, subtree_end_height, root_hash) =
                row.map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;
            if shard_index != u64::try_from(roots.len()).expect("vec length fits in u64") {
                break;
            }
            let root = H::read(Cursor::new(root_hash))
                .map_err(|e| ShardTreeError::Storage(Error::Serialization(e)))?;
            roots.push(CommitmentTreeRoot::from_parts(
                BlockHeight::from(subtree_end_height),
                root,
            ));
        }
        roots
    };

    conn.execute_batch(&format!(
        "DELETE FROM {table_prefix}_tree_checkpoint_marks_removed;
         DELETE FROM {table_prefix}_tree_checkpoints;
         DELETE FROM {table_prefix}_tree_shards;
         DELETE FROM {table_prefix}_tree_cap;"
    ))
    .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;

    put_shard_roots::<H, DEPTH, SHARD_HEIGHT>(conn, table_prefix, 0, &roots)
}

pub(crate) fn add_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), Error> {
    let extant_tree_state = conn
        .query_row(
            &format!(
                "SELECT position FROM {table_prefix}_tree_checkpoints WHERE checkpoint_id = :checkpoint_id"
            ),
            named_params![":checkpoint_id": u32::from(checkpoint_id),],
            |row| {
                row.get::<_, Option<u64>>(0).map(|opt| {
                    opt.map_or_else(
                        || TreeState::Empty,
                        |pos| TreeState::AtPosition(Position::from(pos)),
                    )
                })
            },
        )
        .optional()
        .map_err(Error::Query)?;

    match extant_tree_state {
        Some(current) => {
            if current != checkpoint.tree_state() {
                // If the checkpoint position for a given checkpoint identifier has changed, we treat
                // this as an error because the wallet should have detected a chain reorg and truncated
                // the tree.
                Err(Error::CheckpointConflict {
                    checkpoint_id,
                    checkpoint,
                    extant_tree_state: current,
                    extant_marks_removed: None,
                })
            } else {
                // if the existing spends are the same, we can skip the insert; if the
                // existing spends have changed, this is also a conflict.
                let marks_removed = get_marks_removed(conn, table_prefix, checkpoint_id)?;
                if &marks_removed == checkpoint.marks_removed() {
                    Ok(())
                } else {
                    Err(Error::CheckpointConflict {
                        checkpoint_id,
                        checkpoint,
                        extant_tree_state: current,
                        extant_marks_removed: Some(marks_removed),
                    })
                }
            }
        }
        None => {
            let mut stmt_insert_checkpoint = conn
                .prepare_cached(&format!(
                    "INSERT INTO {table_prefix}_tree_checkpoints (checkpoint_id, position)
                     VALUES (:checkpoint_id, :position)"
                ))
                .map_err(Error::Query)?;

            stmt_insert_checkpoint
                .execute(named_params![
                    ":checkpoint_id": u32::from(checkpoint_id),
                    ":position": checkpoint.position().map(u64::from)
                ])
                .map_err(Error::Query)?;

            let mut stmt_insert_mark_removed = conn
                .prepare_cached(&format!(
                    "INSERT INTO {table_prefix}_tree_checkpoint_marks_removed (checkpoint_id, mark_removed_position)
                     VALUES (:checkpoint_id, :position)"
                ))
                .map_err(Error::Query)?;

            for pos in checkpoint.marks_removed() {
                stmt_insert_mark_removed
                    .execute(named_params![
                        ":checkpoint_id": u32::from(checkpoint_id),
                        ":position": u64::from(*pos)
                    ])
                    .map_err(Error::Query)?;
            }

            Ok(())
        }
    }
}

pub(crate) fn checkpoint_count(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<usize, Error> {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table_prefix}_tree_checkpoints"),
        [],
        |row| row.get::<_, usize>(0),
    )
    .map_err(Error::Query)
}

fn get_marks_removed(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<BTreeSet<Position>, Error> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position
            FROM {table_prefix}_tree_checkpoint_marks_removed
            WHERE checkpoint_id = ?"
        ))
        .map_err(Error::Query)?;
    let mark_removed_rows = stmt
        .query([u32::from(checkpoint_id)])
        .map_err(Error::Query)?;

    mark_removed_rows
        .mapped(|row| row.get::<_, u64>(0).map(Position::from))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(Error::Query)
}

pub(crate) fn get_checkpoint(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<Option<Checkpoint>, Error> {
    let checkpoint_position = conn
        .query_row(
            &format!(
                "SELECT position
                 FROM {table_prefix}_tree_checkpoints
                 WHERE checkpoint_id = ?"
            ),
            [u32::from(checkpoint_id)],
            |row| {
                row.get::<_, Option<u64>>(0)
                    .map(|opt| opt.map(Position::from))
            },
        )
        .optional()
        .map_err(Error::Query)?;

    checkpoint_position
        .map(|pos_opt| {
            Ok(Checkpoint::from_parts(
                pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                get_marks_removed(conn, table_prefix, checkpoint_id)?,
            ))
        })
        .transpose()
}

pub(crate) fn get_max_checkpointed_height(
    conn: &rusqlite::Connection,
    protocol: ShieldedPool,
    target_height: TargetHeight,
    min_confirmations: NonZeroU32,
) -> Result<Option<BlockHeight>, SqliteClientError> {
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(protocol)?;
    let max_checkpoint_height = target_height - u32::from(min_confirmations);

    // We exclude from consideration all checkpoints having heights greater than the maximum
    // checkpoint height. The checkpoint depth is the number of excluded checkpoints + 1.
    conn.query_row(
        &format!(
            "SELECT checkpoint_id
             FROM {table_prefix}_tree_checkpoints
             WHERE checkpoint_id <= :max_checkpoint_height
             ORDER BY checkpoint_id DESC
             LIMIT 1",
        ),
        named_params![":max_checkpoint_height": u32::from(max_checkpoint_height)],
        |row| row.get::<_, u32>(0).map(BlockHeight::from),
    )
    .optional()
    .map_err(SqliteClientError::from)
}

pub(crate) fn get_checkpoint_at_depth(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_depth: usize,
) -> Result<Option<(BlockHeight, Checkpoint)>, rusqlite::Error> {
    let checkpoint_parts = conn
        .query_row(
            &format!(
                "SELECT checkpoint_id, position
                FROM {table_prefix}_tree_checkpoints
                ORDER BY checkpoint_id DESC
                LIMIT 1
                OFFSET :offset",
            ),
            named_params![":offset": checkpoint_depth],
            |row| {
                let checkpoint_id: u32 = row.get(0)?;
                let position: Option<u64> = row.get(1)?;
                Ok((
                    BlockHeight::from(checkpoint_id),
                    position.map(Position::from),
                ))
            },
        )
        .optional()?;

    checkpoint_parts
        .map(|(checkpoint_id, pos_opt)| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT mark_removed_position
                    FROM {table_prefix}_tree_checkpoint_marks_removed
                    WHERE checkpoint_id = ?"
            ))?;
            let mark_removed_rows = stmt.query([u32::from(checkpoint_id)])?;

            let marks_removed = mark_removed_rows
                .mapped(|row| row.get::<_, u64>(0).map(Position::from))
                .collect::<Result<BTreeSet<_>, _>>()?;

            Ok((
                checkpoint_id,
                Checkpoint::from_parts(
                    pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                    marks_removed,
                ),
            ))
        })
        .transpose()
}

pub(crate) fn with_checkpoints<F>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    limit: usize,
    mut callback: F,
) -> Result<(), Error>
where
    F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Error>,
{
    let mut stmt_get_checkpoints = conn
        .prepare_cached(&format!(
            "SELECT checkpoint_id, position
            FROM {table_prefix}_tree_checkpoints
            ORDER BY position
            LIMIT :limit"
        ))
        .map_err(Error::Query)?;

    let mut stmt_get_checkpoint_marks_removed = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position
            FROM {table_prefix}_tree_checkpoint_marks_removed
            WHERE checkpoint_id = :checkpoint_id"
        ))
        .map_err(Error::Query)?;

    let mut rows = stmt_get_checkpoints
        .query(named_params![":limit": limit])
        .map_err(Error::Query)?;

    while let Some(row) = rows.next().map_err(Error::Query)? {
        let checkpoint_id = row.get::<_, u32>(0).map_err(Error::Query)?;
        let tree_state = row
            .get::<_, Option<u64>>(1)
            .map(|opt| opt.map_or_else(|| TreeState::Empty, |p| TreeState::AtPosition(p.into())))
            .map_err(Error::Query)?;

        let mark_removed_rows = stmt_get_checkpoint_marks_removed
            .query(named_params![":checkpoint_id": checkpoint_id])
            .map_err(Error::Query)?;

        let marks_removed = mark_removed_rows
            .mapped(|row| row.get::<_, u64>(0).map(Position::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Error::Query)?;

        callback(
            &BlockHeight::from(checkpoint_id),
            &Checkpoint::from_parts(tree_state, marks_removed),
        )?
    }

    Ok(())
}

pub(crate) fn update_checkpoint_with<F>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    update: F,
) -> Result<bool, Error>
where
    F: Fn(&mut Checkpoint) -> Result<(), Error>,
{
    if let Some(mut c) = get_checkpoint(conn, table_prefix, checkpoint_id)? {
        update(&mut c)?;
        remove_checkpoint(conn, table_prefix, checkpoint_id)?;
        add_checkpoint(conn, table_prefix, checkpoint_id, c)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn remove_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    // cascading delete here obviates the need to manually delete from
    // `tree_checkpoint_marks_removed`
    let mut stmt_delete_checkpoint = conn
        .prepare_cached(&format!(
            "DELETE FROM {table_prefix}_tree_checkpoints
             WHERE checkpoint_id = :checkpoint_id"
        ))
        .map_err(Error::Query)?;

    stmt_delete_checkpoint
        .execute(named_params![":checkpoint_id": u32::from(checkpoint_id),])
        .map_err(Error::Query)?;

    Ok(())
}

pub(crate) fn add_retained_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {table_prefix}_tree_retained_checkpoints (checkpoint_id)
         VALUES (:checkpoint_id)"
    ))
    .map_err(Error::Query)?
    .execute(named_params![":checkpoint_id": u32::from(checkpoint_id)])
    .map_err(Error::Query)?;

    Ok(())
}

pub(crate) fn remove_retained_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "DELETE FROM {table_prefix}_tree_retained_checkpoints
         WHERE checkpoint_id = :checkpoint_id"
    ))
    .map_err(Error::Query)?
    .execute(named_params![":checkpoint_id": u32::from(checkpoint_id)])
    .map_err(Error::Query)?;

    Ok(())
}

pub(crate) fn retained_checkpoints(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<BTreeSet<BlockHeight>, Error> {
    // The retained-checkpoints table is created by a dedicated migration. Tree operations may run
    // against a schema that predates that migration (e.g. when a migration test drives the tree at
    // an intermediate state); such a wallet simply has no retained checkpoints, so report an empty
    // set rather than failing on the missing table.
    let table_name = format!("{table_prefix}_tree_retained_checkpoints");
    let table_exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = :table_name",
            named_params![":table_name": table_name],
            |_| Ok(()),
        )
        .optional()
        .map_err(Error::Query)?
        .is_some();
    if !table_exists {
        return Ok(BTreeSet::new());
    }

    let mut stmt = conn
        .prepare_cached(&format!("SELECT checkpoint_id FROM {table_name}"))
        .map_err(Error::Query)?;
    let rows = stmt.query([]).map_err(Error::Query)?;

    rows.mapped(|row| row.get::<_, u32>(0).map(BlockHeight::from))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(Error::Query)
}

pub(crate) fn truncate_checkpoints_retaining(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    // cascading delete here obviates the need to manually delete from
    // `<protocol>_tree_checkpoint_marks_removed`
    conn.execute(
        &format!("DELETE FROM {table_prefix}_tree_checkpoints WHERE checkpoint_id > ?"),
        [u32::from(checkpoint_id)],
    )
    .map_err(Error::Query)?;

    // we do however need to manually delete any marks associated with the retained checkpoint
    conn.execute(
        &format!(
            "DELETE FROM {table_prefix}_tree_checkpoint_marks_removed WHERE checkpoint_id = ?"
        ),
        [u32::from(checkpoint_id)],
    )
    .map_err(Error::Query)?;

    Ok(())
}

#[tracing::instrument(skip(conn, roots))]
pub(crate) fn put_shard_roots<
    H: Hashable + HashSer + Clone + Eq,
    const DEPTH: u8,
    const SHARD_HEIGHT: u8,
>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    start_index: u64,
    roots: &[CommitmentTreeRoot<H>],
) -> Result<(), ShardTreeError<Error>> {
    if roots.is_empty() {
        // nothing to do
        return Ok(());
    }

    // We treat the cap as a tree with `DEPTH - SHARD_HEIGHT` levels, so that we can make a
    // batch insertion of root data using `Position::from(start_index)` as the starting position
    // and treating the roots as level-0 leaves.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LevelShifter<H, const SHARD_HEIGHT: u8>(H);
    impl<H: Hashable, const SHARD_HEIGHT: u8> Hashable for LevelShifter<H, SHARD_HEIGHT> {
        fn empty_leaf() -> Self {
            Self(H::empty_root(SHARD_HEIGHT.into()))
        }

        fn combine(level: Level, a: &Self, b: &Self) -> Self {
            Self(H::combine(level + SHARD_HEIGHT, &a.0, &b.0))
        }

        fn empty_root(level: Level) -> Self
        where
            Self: Sized,
        {
            Self(H::empty_root(level + SHARD_HEIGHT))
        }
    }
    impl<H: HashSer, const SHARD_HEIGHT: u8> HashSer for LevelShifter<H, SHARD_HEIGHT> {
        fn read<R: io::Read>(reader: R) -> io::Result<Self>
        where
            Self: Sized,
        {
            H::read(reader).map(Self)
        }

        fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
            self.0.write(writer)
        }
    }

    let cap = LocatedTree::from_parts(
        Address::from_parts((DEPTH - SHARD_HEIGHT).into(), 0),
        get_cap::<LevelShifter<H, SHARD_HEIGHT>>(conn, table_prefix)
            .map_err(ShardTreeError::Storage)?,
    )
    .map_err(|e| {
        ShardTreeError::Storage(Error::Serialization(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Note commitment tree cap was invalid at address {e:?}"),
        )))
    })?;

    let insert_into_cap = tracing::info_span!("insert_into_cap").entered();
    let cap_result = cap
        .batch_insert::<(), _>(
            Position::from(start_index),
            roots
                .iter()
                .map(|r| (LevelShifter(r.root_hash().clone()), Retention::Reference)),
        )
        .map_err(ShardTreeError::Insert)?
        .expect("slice of inserted roots was verified to be nonempty");
    drop(insert_into_cap);

    put_cap(conn, table_prefix, cap_result.subtree.take_root()).map_err(ShardTreeError::Storage)?;

    check_shard_discontinuity(
        conn,
        table_prefix,
        start_index..start_index + (roots.len() as u64),
    )
    .map_err(ShardTreeError::Storage)?;

    // We want to avoid deserializing the subtree just to annotate its root node, so we simply
    // cache the downloaded root alongside of any already-persisted subtree. We will update the
    // subtree data itself by reannotating the root node of the tree, handling conflicts, at
    // the time that we deserialize the tree.
    let mut stmt = conn
        .prepare_cached(&format!(
            "INSERT INTO {table_prefix}_tree_shards (shard_index, subtree_end_height, root_hash, shard_data)
            VALUES (:shard_index, :subtree_end_height, :root_hash, :shard_data)
            ON CONFLICT (shard_index) DO UPDATE
            SET subtree_end_height = :subtree_end_height, root_hash = :root_hash"
        ))
        .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;

    let put_roots = tracing::info_span!("write_shards").entered();
    for (root, i) in roots.iter().zip(0u64..) {
        // The `shard_data` value will only be used in the case that no tree already exists.
        let mut shard_data: Vec<u8> = vec![];
        let tree = PrunableTree::leaf((root.root_hash().clone(), RetentionFlags::EPHEMERAL));
        write_shard(&mut shard_data, &tree)
            .map_err(|e| ShardTreeError::Storage(Error::Serialization(e)))?;

        let mut root_hash_data: Vec<u8> = vec![];
        root.root_hash()
            .write(&mut root_hash_data)
            .map_err(|e| ShardTreeError::Storage(Error::Serialization(e)))?;

        stmt.execute(named_params![
            ":shard_index": start_index + i,
            ":subtree_end_height": u32::from(root.subtree_end_height()),
            ":root_hash": root_hash_data,
            ":shard_data": shard_data,
        ])
        .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;
    }
    drop(put_roots);

    Ok(())
}

pub(crate) fn check_witnesses<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    anchor_height: BlockHeight,
) -> Result<Vec<Range<BlockHeight>>, SqliteClientError> {
    let wallet_birthday = super::wallet_birthday(conn)?.ok_or(SqliteClientError::AccountUnknown)?;
    let unspent_sapling_note_meta =
        super::sapling::select_unspent_note_meta(conn, params, wallet_birthday, anchor_height)?;

    let mut scan_ranges = vec![];
    let mut sapling_incomplete = vec![];
    let sapling_tree = sapling_tree(conn)?;
    for m in unspent_sapling_note_meta.iter() {
        match sapling_tree.witness_at_checkpoint_depth(m.commitment_tree_position(), 0) {
            Ok(_) => {}
            Err(ShardTreeError::Query(QueryError::TreeIncomplete(mut addrs))) => {
                sapling_incomplete.append(&mut addrs);
            }
            Err(other) => {
                return Err(SqliteClientError::CommitmentTree(other));
            }
        }
    }

    for addr in sapling_incomplete {
        let range = super::get_block_range(conn, ShieldedPool::Sapling, addr)?;
        scan_ranges.extend(range);
    }

    #[cfg(feature = "orchard")]
    {
        let unspent_orchard_note_meta =
            super::orchard::select_unspent_note_meta(conn, params, wallet_birthday, anchor_height)?;
        let mut orchard_incomplete = vec![];
        let orchard_tree = orchard_tree(conn)?;
        for m in unspent_orchard_note_meta.iter() {
            match orchard_tree.witness_at_checkpoint_depth(m.commitment_tree_position(), 0) {
                Ok(_) => {}
                Err(ShardTreeError::Query(QueryError::TreeIncomplete(mut addrs))) => {
                    orchard_incomplete.append(&mut addrs);
                }
                Err(other) => {
                    return Err(SqliteClientError::CommitmentTree(other));
                }
            }
        }

        for addr in orchard_incomplete {
            let range = super::get_block_range(conn, ShieldedPool::Orchard, addr)?;
            scan_ranges.extend(range);
        }

        let unspent_ironwood_note_meta = super::common::select_unspent_note_meta(
            conn,
            params,
            ShieldedPool::Ironwood,
            wallet_birthday,
            anchor_height,
        )?;
        let mut ironwood_incomplete = vec![];
        let ironwood_tree = ironwood_tree(conn)?;
        for m in unspent_ironwood_note_meta.iter() {
            match ironwood_tree.witness_at_checkpoint_depth(m.commitment_tree_position(), 0) {
                Ok(_) => {}
                Err(ShardTreeError::Query(QueryError::TreeIncomplete(mut addrs))) => {
                    ironwood_incomplete.append(&mut addrs);
                }
                Err(other) => {
                    return Err(SqliteClientError::CommitmentTree(other));
                }
            }
        }

        for addr in ironwood_incomplete {
            let range = super::get_block_range(conn, ShieldedPool::Ironwood, addr)?;
            scan_ranges.extend(range);
        }
    }

    Ok(scan_ranges)
}

/// Generate Orchard Merkle witnesses at a historical height.
///
/// Loads the wallet's Orchard shard data into an ephemeral in-memory
/// [`MemoryShardStore`], inserts the provided frontier at that height as a
/// checkpoint, and generates a witness for each of the given note positions.
///
/// It is assumed that the caller provides the valid frontier at the given height.
///
/// How it works:
/// To construct witnesses at a historical height, we need:
/// 1. Authentication path within each note's shard — the scanner marks the
///    wallet's notes as MARKED, preventing them and their siblings within a
///    shard from being pruned.
/// 2. Cap — the upper tree above the shard level.
/// 3. Frontier — the right edge at the historical height. It lets ShardTree
///    know exactly where the tree ended at that height.
///
/// The wallet automatically prunes the tree after PRUNING_DEPTH checkpoints.
/// These three components are sufficient to reconstruct the tree structure
/// needed for witness generation even after pruning has occurred.
///
/// The wallet DB is strictly read-only. Shard data is read, decoded, and
/// inserted into an ephemeral in-memory [`ShardStore`] to avoid tampering with
/// the primary wallet DB.
///
/// Example application: token holder voting. The wallet tree may have advanced past
/// the historical height, but we need witnesses anchored at that frontier.
///
/// # Errors
///
/// - [`SqliteClientError::CommitmentTree`] if reading the wallet's shard or
///   cap data fails, or if the shard data reconstructed from the wallet is
///   internally inconsistent at a node the computation requires.
/// - [`SqliteClientError::HistoricalFrontierInvalid`] if `frontier_at_height`
///   is inconsistent with the shard data reconstructed from the wallet.
/// - [`SqliteClientError::HistoricalWitnessUnavailable`] if a witness cannot
///   be generated for one of the requested positions at `height` (most
///   commonly because the wallet has not yet synced through that height).
#[cfg(feature = "orchard")]
pub(crate) fn generate_orchard_witnesses_at_historical_height(
    conn: &rusqlite::Connection,
    note_positions: &[Position],
    frontier_at_height: incrementalmerkletree::frontier::NonEmptyFrontier<
        orchard::tree::MerkleHashOrchard,
    >,
    height: BlockHeight,
) -> Result<
    Vec<
        incrementalmerkletree::MerklePath<
            orchard::tree::MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >,
    >,
    SqliteClientError,
> {
    generate_orchard_like_witnesses_at_historical_height(
        conn,
        ORCHARD_TABLES_PREFIX,
        note_positions,
        frontier_at_height,
        height,
    )
}

/// Generates Ironwood Merkle witnesses at a historical height.
///
/// This is identical to [`generate_orchard_witnesses_at_historical_height`],
/// except that it reconstructs witness paths from the Ironwood shard tables.
#[cfg(feature = "orchard")]
pub(crate) fn generate_ironwood_witnesses_at_historical_height(
    conn: &rusqlite::Connection,
    note_positions: &[Position],
    frontier_at_height: incrementalmerkletree::frontier::NonEmptyFrontier<
        orchard::tree::MerkleHashOrchard,
    >,
    height: BlockHeight,
) -> Result<
    Vec<
        incrementalmerkletree::MerklePath<
            orchard::tree::MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >,
    >,
    SqliteClientError,
> {
    generate_orchard_like_witnesses_at_historical_height(
        conn,
        IRONWOOD_TABLES_PREFIX,
        note_positions,
        frontier_at_height,
        height,
    )
}

#[cfg(feature = "orchard")]
fn generate_orchard_like_witnesses_at_historical_height(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    note_positions: &[Position],
    frontier_at_height: incrementalmerkletree::frontier::NonEmptyFrontier<
        orchard::tree::MerkleHashOrchard,
    >,
    height: BlockHeight,
) -> Result<
    Vec<
        incrementalmerkletree::MerklePath<
            orchard::tree::MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >,
    >,
    SqliteClientError,
> {
    // `get_shard_roots` returns addresses ordered by shard index, matching the
    // ascending insertion order required by `MemoryShardStore::put_shard`.
    // Storage errors flow through `From<ShardTreeError<commitment_tree::Error>>`
    // into `SqliteClientError::CommitmentTree`.
    let mut store = MemoryShardStore::<orchard::tree::MerkleHashOrchard, BlockHeight>::empty();
    let shard_root_level = Level::new(ORCHARD_SHARD_HEIGHT);
    let shard_roots =
        get_shard_roots(conn, table_prefix, shard_root_level).map_err(ShardTreeError::Storage)?;
    for shard_root in shard_roots {
        if let Some(shard) =
            get_shard::<orchard::tree::MerkleHashOrchard>(conn, table_prefix, shard_root)
                .map_err(ShardTreeError::Storage)?
        {
            store.put_shard(shard).expect("put_shard is infallible");
        }
    }
    let cap = get_cap::<orchard::tree::MerkleHashOrchard>(conn, table_prefix)
        .map_err(ShardTreeError::Storage)?;
    store.put_cap(cap).expect("put_cap is infallible");

    // Only one checkpoint is needed (the historical frontier), but `ShardTree`
    // requires a nonzero checkpoint limit.
    //
    // Pruning-safety invariant: `MemoryShardStore::empty()` starts with zero
    // checkpoints in its internal `BTreeMap`, and the only mutations above
    // (`put_shard` / `put_cap`) do not touch that map (the `CHECKPOINT`
    // retention flags stored *inside* shard leaves are independent of the
    // store's `checkpoint_count()`). So when `insert_frontier_nodes` below
    // calls `add_checkpoint` exactly once and then `prune_excess_checkpoints`,
    // we have `1 > 1 == false` and the freshly inserted historical checkpoint
    // is NOT pruned away before `witness_at_checkpoint_id` reads it.
    //
    // If this code is changed to (a) pre-load wallet checkpoints into the
    // in-memory store, (b) add an extra `add_checkpoint` call here, or
    // (c) drop `max_checkpoints` below `1`, the historical checkpoint will be
    // pruned immediately and witness generation will return
    // `HistoricalWitnessUnavailable` at the `witness_at_checkpoint_id` call
    // below. The `witnesses_at_historical_height_with_many_wallet_checkpoints`
    // test in `mod tests` exists to catch exactly that regression.
    let mut tree =
        ShardTree::<_, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }, ORCHARD_SHARD_HEIGHT>::new(
            store, 1,
        );

    // Insert the frontier. `Retention::Checkpoint` causes `ShardTree` to
    // register a checkpoint at `height` internally; the pruning-safety
    // invariant above guarantees it survives the `prune_excess_checkpoints`
    // pass that runs at the end of `insert_frontier_nodes`.
    //
    // `MemoryShardStore::Error` is `Infallible`, so the only variants of
    // `ShardTreeError` we can observe are `Insert` (a caller-supplied
    // frontier inconsistent with the loaded shards) and `Query` (an
    // inconsistency in the loaded shards themselves).
    tree.insert_frontier_nodes(
        frontier_at_height,
        Retention::Checkpoint {
            id: height,
            marking: Marking::None,
        },
    )
    .map_err(|e| match e {
        ShardTreeError::Insert(e) => SqliteClientError::HistoricalFrontierInvalid(e),
        ShardTreeError::Query(q) => SqliteClientError::CommitmentTree(ShardTreeError::Query(q)),
        ShardTreeError::Storage(inf) => match inf {},
    })?;

    // Generate a witness per note position. Any `Query` failure (or a `None`
    // result) at this stage means the tree reconstructed from the wallet's
    // shards does not contain enough information to compute a witness at
    // `height`; we surface that as `HistoricalWitnessUnavailable` so the
    // caller can either sync further or stop requesting that position.
    let mut witnesses = Vec::with_capacity(note_positions.len());
    for &pos in note_positions {
        let merkle_path = tree
            .witness_at_checkpoint_id(pos, &height)
            .map_err(|e| match e {
                ShardTreeError::Query(_) => SqliteClientError::HistoricalWitnessUnavailable {
                    position: pos,
                    height,
                },
                ShardTreeError::Insert(i) => {
                    SqliteClientError::CommitmentTree(ShardTreeError::Insert(i))
                }
                ShardTreeError::Storage(inf) => match inf {},
            })?
            .ok_or(SqliteClientError::HistoricalWitnessUnavailable {
                position: pos,
                height,
            })?;

        witnesses.push(merkle_path);
    }

    Ok(witnesses)
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use incrementalmerkletree::{Marking, Position, Retention};
    use incrementalmerkletree_testing::{
        check_append, check_checkpoint_rewind, check_remove_mark, check_rewind_remove_mark,
        check_root_hashes, check_witness_consistency, check_witnesses,
    };
    use shardtree::{ShardTree, error::ShardTreeError, store::ShardStore};
    use zcash_client_backend::data_api::{
        WalletCommitmentTrees,
        chain::CommitmentTreeRoot,
        testing::{pool::ShieldedPoolTester, sapling::SaplingPoolTester},
    };
    use zcash_protocol::consensus::{BlockHeight, Network};

    use super::SqliteShardStore;
    use crate::{
        WalletDb,
        testing::{
            db::{test_clock, test_rng},
            pool::ShieldedPoolPersistence,
        },
        wallet::init::WalletMigrator,
    };
    // Used only by the orchard-gated `HistoricalWitnessGenerator` type alias below.
    use std::collections::BTreeSet;
    #[cfg(feature = "orchard")]
    use {
        crate::error::SqliteClientError, ::orchard::tree::MerkleHashOrchard,
        incrementalmerkletree::frontier::Frontier, rand::SeedableRng, rand_chacha::ChaChaRng,
        zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
    };

    fn new_tree<T: ShieldedPoolTester + ShieldedPoolPersistence>(
        m: usize,
    ) -> ShardTree<SqliteShardStore<rusqlite::Connection, String, 3>, 4, 3> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        data_file.keep().unwrap();

        WalletMigrator::new().init_or_migrate(&mut db_data).unwrap();
        let store =
            SqliteShardStore::<_, String, 3>::from_connection(db_data.conn, T::TABLES_PREFIX)
                .unwrap();
        ShardTree::new(store, m)
    }

    fn check_retained_checkpoints(
        mut tree: ShardTree<SqliteShardStore<rusqlite::Connection, String, 3>, 4, 3>,
    ) {
        let h1 = BlockHeight::from(100);
        let h2 = BlockHeight::from(200);

        assert!(tree.store().retained_checkpoints().unwrap().is_empty());

        tree.ensure_retained(h1).unwrap();
        tree.ensure_retained(h2).unwrap();
        // Retaining an already-retained checkpoint is idempotent.
        tree.ensure_retained(h1).unwrap();
        assert_eq!(
            tree.store().retained_checkpoints().unwrap(),
            BTreeSet::from([h1, h2])
        );

        tree.remove_retained_checkpoint(&h1).unwrap();
        assert_eq!(
            tree.store().retained_checkpoints().unwrap(),
            BTreeSet::from([h2])
        );
    }

    #[cfg(feature = "orchard")]
    mod orchard {
        use super::new_tree;
        use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;

        #[test]
        fn append() {
            super::check_append(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn root_hashes() {
            super::check_root_hashes(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn witnesses() {
            super::check_witnesses(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn witness_consistency() {
            super::check_witness_consistency(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn checkpoint_rewind() {
            super::check_checkpoint_rewind(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn remove_mark() {
            super::check_remove_mark(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn rewind_remove_mark() {
            super::check_rewind_remove_mark(new_tree::<OrchardPoolTester>);
        }

        #[test]
        fn witnesses_at_historical_height() {
            super::witnesses_at_historical_height()
        }

        #[test]
        fn ironwood_witnesses_at_historical_height() {
            super::ironwood_witnesses_at_historical_height()
        }

        #[test]
        fn witnesses_at_historical_height_with_many_wallet_checkpoints() {
            super::witnesses_at_historical_height_with_many_wallet_checkpoints()
        }

        #[test]
        fn put_shard_roots() {
            super::put_shard_roots::<OrchardPoolTester>()
        }

        #[test]
        fn retained_checkpoints() {
            super::check_retained_checkpoints(super::new_tree::<OrchardPoolTester>(10));
        }
    }

    #[test]
    fn sapling_append() {
        check_append(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_retained_checkpoints() {
        check_retained_checkpoints(new_tree::<SaplingPoolTester>(10));
    }

    #[test]
    fn remove_retained_checkpoints_below() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();

        db.with_sapling_tree_mut(|tree| {
            for h in [100u32, 200, 300] {
                tree.ensure_retained(BlockHeight::from(h))?;
            }
            Ok::<_, ShardTreeError<_>>(())
        })
        .unwrap();

        #[cfg(feature = "orchard")]
        {
            db.with_orchard_tree_mut(|tree| {
                for h in [100u32, 200, 300] {
                    tree.ensure_retained(BlockHeight::from(h))?;
                }
                Ok::<_, ShardTreeError<_>>(())
            })
            .unwrap();

            db.with_ironwood_tree_mut(|tree| {
                for h in [100u32, 200, 300] {
                    tree.ensure_retained(BlockHeight::from(h))?;
                }
                Ok::<_, ShardTreeError<_>>(())
            })
            .unwrap();
        }

        db.remove_retained_checkpoints_below(BlockHeight::from(250))
            .unwrap();

        let remaining = db
            .with_sapling_tree_mut(|tree| {
                tree.store()
                    .retained_checkpoints()
                    .map_err(ShardTreeError::Storage)
            })
            .unwrap();
        assert_eq!(remaining, BTreeSet::from([BlockHeight::from(300)]));

        // The retained checkpoints must be pruned in the Orchard and Ironwood trees as well, not
        // just Sapling.
        #[cfg(feature = "orchard")]
        {
            let orchard_remaining = db
                .with_orchard_tree_mut(|tree| {
                    tree.store()
                        .retained_checkpoints()
                        .map_err(ShardTreeError::Storage)
                })
                .unwrap();
            assert_eq!(orchard_remaining, BTreeSet::from([BlockHeight::from(300)]));

            let ironwood_remaining = db
                .with_ironwood_tree_mut(|tree| {
                    tree.store()
                        .retained_checkpoints()
                        .map_err(ShardTreeError::Storage)
                })
                .unwrap()
                .expect("the wallet tracks an Ironwood tree");
            assert_eq!(
                ironwood_remaining,
                BTreeSet::from([BlockHeight::from(300)]),
                "retained Ironwood checkpoints below the max height must be released",
            );
        }
    }

    #[test]
    fn sapling_root_hashes() {
        check_root_hashes(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_witnesses() {
        check_witnesses(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_witness_consistency() {
        check_witness_consistency(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_checkpoint_rewind() {
        check_checkpoint_rewind(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_remove_mark() {
        check_remove_mark(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_rewind_remove_mark() {
        check_rewind_remove_mark(new_tree::<SaplingPoolTester>);
    }

    #[test]
    fn sapling_put_shard_roots() {
        put_shard_roots::<SaplingPoolTester>()
    }

    fn put_shard_roots<T: ShieldedPoolTester + ShieldedPoolPersistence>() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        data_file.keep().unwrap();

        WalletMigrator::new().init_or_migrate(&mut db_data).unwrap();
        let tx = db_data.conn.transaction().unwrap();
        let store =
            SqliteShardStore::<_, String, 3>::from_connection(&tx, T::TABLES_PREFIX).unwrap();

        // introduce some roots
        let roots = (0u32..4)
            .map(|idx| {
                CommitmentTreeRoot::from_parts(
                    BlockHeight::from((idx + 1) * 3),
                    if idx == 3 {
                        "abcdefgh".to_string()
                    } else {
                        idx.to_string()
                    },
                )
            })
            .collect::<Vec<_>>();
        super::put_shard_roots::<_, 6, 3>(store.conn, T::TABLES_PREFIX, 0, &roots).unwrap();

        // simulate discovery of a note
        let mut tree = ShardTree::<_, 6, 3>::new(store, 10);
        let checkpoint_height = BlockHeight::from(3);
        tree.batch_insert(
            Position::from(24),
            ('a'..='h').map(|c| {
                (
                    c.to_string(),
                    match c {
                        'c' => Retention::Marked,
                        'h' => Retention::Checkpoint {
                            id: checkpoint_height,
                            marking: Marking::None,
                        },
                        _ => Retention::Ephemeral,
                    },
                )
            }),
        )
        .unwrap();

        // construct a witness for the note
        let witness = tree
            .witness_at_checkpoint_id(Position::from(26), &checkpoint_height)
            .unwrap();
        assert_eq!(
            witness
                .expect("an anchor exists at the expected checkpoint height")
                .path_elems(),
            &[
                "d",
                "ab",
                "efgh",
                "2",
                "01",
                "________________________________"
            ]
        );
    }

    /// Test that `generate_orchard_witnesses_at_historical_height` produces valid
    /// witnesses when given a frontier extracted from an earlier tree state.
    #[cfg(feature = "orchard")]
    fn witnesses_at_historical_height() {
        witnesses_at_historical_height_for_table(
            crate::ORCHARD_TABLES_PREFIX,
            super::generate_orchard_witnesses_at_historical_height,
        )
    }

    /// Test that `generate_ironwood_witnesses_at_historical_height` uses the
    /// Ironwood shard tables rather than the Orchard shard tables.
    #[cfg(feature = "orchard")]
    fn ironwood_witnesses_at_historical_height() {
        witnesses_at_historical_height_for_table(
            crate::IRONWOOD_TABLES_PREFIX,
            super::generate_ironwood_witnesses_at_historical_height,
        )
    }

    #[cfg(feature = "orchard")]
    type OrchardFrontier =
        incrementalmerkletree::frontier::NonEmptyFrontier<::orchard::tree::MerkleHashOrchard>;

    #[cfg(feature = "orchard")]
    type OrchardMerklePath = incrementalmerkletree::MerklePath<
        ::orchard::tree::MerkleHashOrchard,
        { ::orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
    >;

    #[cfg(feature = "orchard")]
    type HistoricalWitnessGenerator = fn(
        &rusqlite::Connection,
        &[Position],
        OrchardFrontier,
        BlockHeight,
    ) -> Result<Vec<OrchardMerklePath>, SqliteClientError>;

    #[cfg(feature = "orchard")]
    fn witnesses_at_historical_height_for_table(
        table_prefix: &'static str,
        generate_witnesses: HistoricalWitnessGenerator,
    ) {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        data_file.keep().unwrap();

        WalletMigrator::new().init_or_migrate(&mut db_data).unwrap();

        let mut rng = ChaChaRng::seed_from_u64(0);

        // We build two parallel trees: the wallet's ShardTree (persisted to the DB)
        // and a lightweight Frontier that captures the tree state at the historical height.
        let mut frontier_tree: Frontier<MerkleHashOrchard, 32> = Frontier::empty();
        let historical_height = BlockHeight::from(100);
        let note_position = Position::from(2);
        let note_leaf;

        {
            let tx = db_data.conn.transaction().unwrap();
            let store =
                SqliteShardStore::<_, MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>::from_connection(
                    &tx,
                    table_prefix,
                )
                .unwrap();
            let mut tree = ShardTree::<
                _,
                { ::orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
                ORCHARD_SHARD_HEIGHT,
            >::new(store, 100);

            let mut leaves = Vec::new();
            for _ in 0u64..5 {
                leaves.push(MerkleHashOrchard::random(&mut rng));
            }
            note_leaf = leaves[u64::from(note_position) as usize];

            for (i, &leaf) in leaves.iter().enumerate() {
                let retention = if i == u64::from(note_position) as usize {
                    Retention::Marked
                } else {
                    Retention::Ephemeral
                };
                tree.append(leaf, retention).unwrap();
                frontier_tree.append(leaf);
            }

            // Advance the tree past the historical height, simulating the
            // wallet continuing to sync afterward.
            tree.checkpoint(historical_height).unwrap();
            for _ in 0..5 {
                tree.append(MerkleHashOrchard::random(&mut rng), Retention::Ephemeral)
                    .unwrap();
            }
            tree.checkpoint(BlockHeight::from(200)).unwrap();

            tx.commit().unwrap();
        }

        let expected_root = frontier_tree.root();
        let frontier = frontier_tree.take().expect("frontier is non-empty");

        let witnesses =
            generate_witnesses(&db_data.conn, &[note_position], frontier, historical_height)
                .expect("witness generation should succeed");

        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].root(note_leaf), expected_root);
    }

    /// Regression test: `generate_orchard_witnesses_at_historical_height` must not
    /// lose its freshly inserted historical checkpoint to pruning, even when the
    /// wallet has advanced many checkpoints past the historical height (so that
    /// the historical checkpoint has long since been pruned from the wallet's own
    /// `ShardTree`).
    ///
    /// Flow:
    /// 1. Seed: append 2 leaves to the wallet's `ShardTree` (position 0
    ///    `Marked`, position 1 `Ephemeral`), mirror them into a parallel
    ///    `Frontier` to capture the ground-truth state, then `checkpoint` at
    ///    `historical_height = 10`.
    /// 2. Bury: append 249 more `Ephemeral`-only blocks, each with its own
    ///    checkpoint. With `WALLET_MAX_CHECKPOINTS = 100` the wallet's pruner
    ///    evicts checkpoints 10..=159, including the one at
    ///    `historical_height`. The `Marked` retention at position 0 survives
    ///    because no surviving checkpoint schedules it for unmarking.
    /// 3. Precondition: assert `min_checkpoint_id > historical_height` so the
    ///    test fails loudly if a future tweak (e.g. shrinking `TOTAL_BLOCKS`
    ///    or growing `WALLET_MAX_CHECKPOINTS`) accidentally leaves the
    ///    historical checkpoint alive in the DB.
    /// 4. Exercise: call `generate_orchard_witnesses_at_historical_height`
    ///    with the captured frontier. Internally it builds a fresh
    ///    `MemoryShardStore` (no checkpoints), `ShardTree::new(store, 1)`,
    ///    and `insert_frontier_nodes(.., Retention::Checkpoint { id: 10 })`,
    ///    which adds exactly one checkpoint and then runs
    ///    `prune_excess_checkpoints` (`1 > 1` is false, so no eviction).
    /// 5. Verify: witness generation returns `Ok`, and
    ///    `witness.root(note_leaf) == frontier_tree.root()` confirms the
    ///    reconstructed anchor matches the historical state captured in (1).
    ///
    /// If anyone later changes the in-memory `max_checkpoints` to `0`, copies
    /// wallet checkpoints into the in-memory store, or otherwise inflates
    /// `checkpoint_count` before the frontier insertion, the freshly added
    /// historical checkpoint would be pruned and `witness_at_checkpoint_id`
    /// would return `None`, surfacing the regression as
    /// `SqliteClientError::HistoricalWitnessUnavailable`.
    #[cfg(feature = "orchard")]
    fn witnesses_at_historical_height_with_many_wallet_checkpoints() {
        // Wallet tree capacity << number of blocks we sync, so the historical
        // checkpoint is forcibly pruned from the wallet's own ShardTree before
        // we attempt to generate a witness at that height.
        const WALLET_MAX_CHECKPOINTS: usize = 100;
        const TOTAL_BLOCKS: u32 = 250;
        const LEAVES_PER_BLOCK: usize = 2;

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        data_file.keep().unwrap();

        WalletMigrator::new().init_or_migrate(&mut db_data).unwrap();

        let mut rng = ChaChaRng::seed_from_u64(1);

        let mut frontier_tree: Frontier<MerkleHashOrchard, 32> = Frontier::empty();
        let historical_height = BlockHeight::from(10);
        let note_position = Position::from(0);
        let note_leaf;

        {
            let tx = db_data.conn.transaction().unwrap();
            let store =
                SqliteShardStore::<_, MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>::from_connection(
                    &tx, "orchard",
                )
                .unwrap();
            let mut tree = ShardTree::<
                _,
                { ::orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
                ORCHARD_SHARD_HEIGHT,
            >::new(store, WALLET_MAX_CHECKPOINTS);

            // First block: mark the note, snapshot the frontier, then checkpoint
            // at `historical_height`.
            let note_idx = u64::from(note_position) as usize;
            let mut first_leaves = Vec::with_capacity(LEAVES_PER_BLOCK);
            for _ in 0..LEAVES_PER_BLOCK {
                first_leaves.push(MerkleHashOrchard::random(&mut rng));
            }
            note_leaf = first_leaves[note_idx];
            for (i, &leaf) in first_leaves.iter().enumerate() {
                let retention = if i == note_idx {
                    Retention::Marked
                } else {
                    Retention::Ephemeral
                };
                tree.append(leaf, retention).unwrap();
                frontier_tree.append(leaf);
            }
            tree.checkpoint(historical_height).unwrap();

            // Drive the wallet far past the historical height so its pruner
            // evicts the historical_height checkpoint from the SQLite store.
            for block in 1..TOTAL_BLOCKS {
                for _ in 0..LEAVES_PER_BLOCK {
                    tree.append(MerkleHashOrchard::random(&mut rng), Retention::Ephemeral)
                        .unwrap();
                }
                tree.checkpoint(historical_height + block).unwrap();
            }
            tx.commit().unwrap();
        }

        // Sanity-check the precondition: the historical checkpoint must no
        // longer be present in the wallet's checkpoint table.
        let min_ckpt = super::min_checkpoint_id(&db_data.conn, "orchard")
            .unwrap()
            .expect("wallet has checkpoints");
        assert!(
            min_ckpt > historical_height,
            "test precondition: historical checkpoint should have been pruned, \
             but min retained checkpoint is {min_ckpt:?} <= {historical_height:?}",
        );

        let expected_root = frontier_tree.root();
        let frontier = frontier_tree.take().expect("frontier is non-empty");

        let witnesses = super::generate_orchard_witnesses_at_historical_height(
            &db_data.conn,
            &[note_position],
            frontier,
            historical_height,
        )
        .expect("witness generation should succeed despite deep wallet pruning");

        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].root(note_leaf), expected_root);
    }

    /// Logical dump of the tree, note, and block tables. Blobs are hex. `account_id` is omitted
    /// because account UUIDs are random and are not part of the tree.
    fn dump_wallet_trees(conn: &rusqlite::Connection) -> String {
        let mut tables = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table'
                 AND (name LIKE '%tree_%' OR name LIKE '%received_note%' OR name = 'blocks')
                 ORDER BY name",
            )
            .unwrap();
        let names = tables
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut out = String::new();
        for name in names {
            let mut info = conn
                .prepare(&format!("PRAGMA table_info(\"{name}\")"))
                .unwrap();
            let columns = info
                .query_map([], |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let projected = columns
                .into_iter()
                .filter(|(column, _)| column != "account_id")
                .map(|(column, ty)| {
                    let quoted = format!("\"{column}\"");
                    let selected = if ty.to_ascii_uppercase().contains("BLOB") {
                        format!("hex({quoted})")
                    } else {
                        quoted.clone()
                    };
                    (selected, quoted)
                })
                .collect::<Vec<_>>();
            if projected.is_empty() {
                continue;
            }
            let order = projected
                .iter()
                .take(3)
                .map(|(_, quoted)| quoted.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT {} FROM \"{name}\" ORDER BY {order}",
                projected
                    .iter()
                    .map(|(selected, _)| selected.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            out.push_str(&name);
            out.push('\n');
            let mut stmt = conn.prepare(&sql).unwrap();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let width = projected.len();
                for index in 0..width {
                    if index > 0 {
                        out.push('\t');
                    }
                    match row.get_ref(index).unwrap() {
                        rusqlite::types::ValueRef::Null => out.push_str("NULL"),
                        rusqlite::types::ValueRef::Integer(value) => {
                            out.push_str(&value.to_string())
                        }
                        rusqlite::types::ValueRef::Real(value) => out.push_str(&value.to_string()),
                        rusqlite::types::ValueRef::Text(value) => {
                            out.push_str(&String::from_utf8_lossy(value))
                        }
                        rusqlite::types::ValueRef::Blob(value) => out.push_str(&hex::encode(value)),
                    }
                }
                out.push('\n');
            }
        }
        out
    }

    fn assert_same_dump(immediate: &str, write_back: &str) {
        if immediate == write_back {
            return;
        }
        for (index, (left, right)) in immediate.lines().zip(write_back.lines()).enumerate() {
            if left != right {
                panic!(
                    "wallet dump mismatch at line {index}:\n  immediate: {left}\n  write-back: {right}"
                );
            }
        }
        panic!(
            "wallet dump length mismatch (immediate {} lines, write-back {} lines)",
            immediate.lines().count(),
            write_back.lines().count()
        );
    }

    fn migrated_tree_file() -> (tempfile::NamedTempFile, rusqlite::Connection) {
        let data_file = tempfile::NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db_data).unwrap();
        // Drop the migrating connection before the tests open their own.
        drop(db_data);
        let conn = rusqlite::Connection::open(data_file.path()).unwrap();
        (data_file, conn)
    }

    fn drive_shard_phase1<S>(tree: &mut ShardTree<S, 6, 3>)
    where
        S: ShardStore<H = String, CheckpointId = BlockHeight>,
    {
        tree.insert_frontier(
            incrementalmerkletree::frontier::Frontier::<String, 6>::empty(),
            Retention::Checkpoint {
                id: BlockHeight::from(0),
                marking: Marking::None,
            },
        )
        .unwrap();
        for i in 1..=40u32 {
            let marking = if i % 4 == 0 {
                Marking::Marked
            } else {
                Marking::None
            };
            tree.append(
                format!("leaf-{i}"),
                Retention::Checkpoint {
                    id: BlockHeight::from(i),
                    marking,
                },
            )
            .unwrap();
            if i % 10 == 0 {
                tree.ensure_retained(BlockHeight::from(i)).unwrap();
            }
        }
    }

    fn drive_shard_phase2<S>(tree: &mut ShardTree<S, 6, 3>)
    where
        S: ShardStore<H = String, CheckpointId = BlockHeight>,
    {
        assert!(
            tree.remove_mark(Position::from(3), Some(&BlockHeight::from(40)))
                .unwrap()
        );
        assert!(tree.truncate_to_checkpoint(&BlockHeight::from(20)).unwrap());
        for i in 41..=50u32 {
            tree.append(
                format!("leaf-{i}"),
                Retention::Checkpoint {
                    id: BlockHeight::from(i),
                    marking: Marking::None,
                },
            )
            .unwrap();
        }
    }

    /// The write-back cache and the immediate SQLite store leave the same shard, cap, checkpoint,
    /// mark, and anchor-retention rows, including across a rewind and a second batch.
    #[test]
    fn write_back_matches_immediate_shard_store() {
        let prefix = SaplingPoolTester::TABLES_PREFIX;
        let (_immediate_file, immediate_conn) = migrated_tree_file();
        let mut immediate = ShardTree::new(
            SqliteShardStore::<_, String, 3>::from_connection(immediate_conn, prefix).unwrap(),
            8,
        );
        let (_write_back_file, mut write_back_conn) = migrated_tree_file();

        drive_shard_phase1(&mut immediate);
        {
            let tx = write_back_conn.transaction().unwrap();
            let mut store = SqliteShardStore::<_, String, 3>::from_connection(&tx, prefix).unwrap();
            store.enable_write_back().unwrap();
            let mut tree = ShardTree::new(store, 8);
            drive_shard_phase1(&mut tree);
            tree.store_mut().flush_write_back().unwrap();
            drop(tree);
            tx.commit().unwrap();
        }
        assert_same_dump(
            &dump_wallet_trees(&immediate.store().conn),
            &dump_wallet_trees(&write_back_conn),
        );

        drive_shard_phase2(&mut immediate);
        {
            let tx = write_back_conn.transaction().unwrap();
            let mut store = SqliteShardStore::<_, String, 3>::from_connection(&tx, prefix).unwrap();
            store.enable_write_back().unwrap();
            let mut tree = ShardTree::new(store, 8);
            drive_shard_phase2(&mut tree);
            tree.store_mut().flush_write_back().unwrap();
            drop(tree);
            tx.commit().unwrap();
        }
        assert_same_dump(
            &dump_wallet_trees(&immediate.store().conn),
            &dump_wallet_trees(&write_back_conn),
        );
    }

    /// Dropping a write-back batch without committing leaves the on-disk tree untouched.
    #[test]
    fn write_back_rollback_leaves_shard_store_unchanged() {
        let prefix = SaplingPoolTester::TABLES_PREFIX;
        let (file, mut conn) = migrated_tree_file();
        {
            let tx = conn.transaction().unwrap();
            let mut store = SqliteShardStore::<_, String, 3>::from_connection(&tx, prefix).unwrap();
            store.enable_write_back().unwrap();
            let mut tree = ShardTree::new(store, 8);
            drive_shard_phase1(&mut tree);
            tree.store_mut().flush_write_back().unwrap();
            drop(tree);
            tx.commit().unwrap();
        }
        let committed = dump_wallet_trees(&conn);
        drop(conn);

        {
            let mut conn = rusqlite::Connection::open(file.path()).unwrap();
            let tx = conn.transaction().unwrap();
            let mut store = SqliteShardStore::<_, String, 3>::from_connection(&tx, prefix).unwrap();
            store.enable_write_back().unwrap();
            let mut tree: ShardTree<_, 6, 3> = ShardTree::new(store, 8);
            // Mutate the cache, then abandon the transaction before flush or commit.
            tree.append(
                "cancelled".to_string(),
                Retention::Checkpoint {
                    id: BlockHeight::from(100),
                    marking: Marking::None,
                },
            )
            .unwrap();
            drop(tree);
            drop(tx);
        }

        let conn = rusqlite::Connection::open(file.path()).unwrap();
        assert_same_dump(&committed, &dump_wallet_trees(&conn));
    }

    /// A tree callback that fails after mutating the cache does not commit those mutations.
    #[test]
    fn write_back_callback_error_rolls_back() {
        use crate::testing::{BlockCache, db::TestDbFactory};
        use zcash_client_backend::data_api::{WalletCommitmentTrees, testing::TestBuilder};
        use zcash_primitives::block::BlockHash;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let before = dump_wallet_trees(st.wallet().conn());

        #[derive(Debug)]
        struct Cancelled;
        impl From<ShardTreeError<super::Error>> for Cancelled {
            fn from(err: ShardTreeError<super::Error>) -> Self {
                panic!("tree update failed before the intentional cancel: {err:?}");
            }
        }

        let result: Result<(), Cancelled> = st.wallet_mut().with_sapling_tree_mut(|tree| {
            tree.ensure_retained(BlockHeight::from(1_000_000))?;
            Err(Cancelled)
        });
        assert!(result.is_err());
        assert_same_dump(&before, &dump_wallet_trees(st.wallet().conn()));
    }

    /// Scanning, spending, rewinding, and rescanning on the write-back cache produces the same
    /// commitment trees, notes, witnesses, and checkpoints as the immediate store.
    #[test]
    fn write_back_matches_immediate_wallet_scan() {
        use crate::testing::{BlockCache, db::TestDb, db::TestDbFactory};
        use zcash_client_backend::data_api::{
            WalletWrite,
            testing::{
                AddressType, TestBuilder, TestState, pool::ShieldedPoolTester,
                sapling::SaplingPoolTester,
            },
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

        fn fresh(write_back: bool) -> TestState<BlockCache, TestDb, LocalNetwork> {
            let mut st = TestBuilder::new()
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();
            st.wallet_mut()
                .db_mut()
                .set_commitment_tree_write_back(write_back);
            st
        }

        fn scan_from(
            st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
            start: BlockHeight,
            count: u32,
        ) {
            let mut scanned = 0u32;
            while scanned < count {
                let chunk = (count - scanned).min(30);
                let height = BlockHeight::from(u32::from(start) + scanned);
                st.scan_cached_blocks(height, usize::try_from(chunk).unwrap());
                scanned += chunk;
            }
        }

        fn drive(st: &mut TestState<BlockCache, TestDb, LocalNetwork>) {
            let dfvk = SaplingPoolTester::test_account_fvk(st);
            let value = Zatoshis::const_from_u64(10_000);
            let mut first = None;
            let mut last_nf = None;
            // More blocks than `PRUNING_DEPTH` (100), so checkpoint pruning runs.
            for _ in 0..105 {
                let (height, _, nf) =
                    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
                first.get_or_insert(height);
                last_nf = Some(nf);
            }
            let start = first.expect("generated a block");
            scan_from(st, start, 105);

            let recipient = SaplingPoolTester::fvk_default_address(&SaplingPoolTester::sk_to_fvk(
                &SaplingPoolTester::sk(&[0xf5; 32]),
            ));
            let (spend_height, _) = st.generate_next_block_spending(
                &dfvk,
                (last_nf.expect("received a note"), value),
                recipient,
                Zatoshis::const_from_u64(4_000),
            );
            st.scan_cached_blocks(spend_height, 1);

            let rewind = BlockHeight::from(u32::from(spend_height) - 5);
            st.wallet_mut().truncate_to_height(rewind).unwrap();
            let rescan = u32::from(spend_height) - u32::from(rewind);
            scan_from(st, BlockHeight::from(u32::from(rewind) + 1), rescan);

            for _ in 0..3 {
                let (height, _, _) =
                    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
                st.scan_cached_blocks(height, 1);
            }
        }

        let mut immediate = fresh(false);
        let mut cached = fresh(true);
        drive(&mut immediate);
        drive(&mut cached);
        assert_same_dump(
            &dump_wallet_trees(immediate.wallet().conn()),
            &dump_wallet_trees(cached.wallet().conn()),
        );
    }

    /// One `insert_tree` per shard must persist the same rows as one `insert_tree` per leaf.
    ///
    /// `put_blocks` builds note-commitment subtrees in parallel and inserts each one. Pruning
    /// runs at the end of every insert, so a small chunk rewrites the frontier shard once per
    /// chunk. A chunk the size of a shard does that once. The flushed rows have to match.
    #[test]
    fn shard_sized_chunks_match_per_leaf_insert() {
        use incrementalmerkletree::frontier::Frontier;
        use zcash_client_backend::data_api::ll::wallet::{build_subtrees, update_tree};

        fn apply(chunk: usize) -> String {
            let (_file, conn) = migrated_tree_file();
            let store = SqliteShardStore::<_, String, 3>::from_connection(
                conn,
                SaplingPoolTester::TABLES_PREFIX,
            )
            .unwrap();
            let mut tree = ShardTree::<_, 6, 3>::new(store, 4);
            let mut leaves = (1..=40u32)
                .map(|i| {
                    Some((
                        format!("leaf-{i}"),
                        Retention::Checkpoint {
                            id: BlockHeight::from(i),
                            marking: if i % 4 == 0 {
                                Marking::Marked
                            } else {
                                Marking::None
                            },
                        },
                    ))
                })
                .collect::<Vec<_>>();
            let subtrees = build_subtrees::<String, 3>(Position::from(0), &mut leaves, chunk);
            update_tree(
                "chunk",
                &Frontier::<String, 6>::empty(),
                BlockHeight::from(0),
                &mut tree,
                None,
                subtrees.into_iter(),
                #[cfg(feature = "orchard")]
                std::iter::empty(),
            )
            .unwrap();
            dump_wallet_trees(&tree.store().conn)
        }

        let per_leaf = apply(1);
        assert_same_dump(&per_leaf, &apply(2));
        assert_same_dump(&per_leaf, &apply(8));
        assert_same_dump(&per_leaf, &apply(64));

        let (_file, conn) = migrated_tree_file();
        let store = SqliteShardStore::<_, String, 3>::from_connection(
            conn,
            SaplingPoolTester::TABLES_PREFIX,
        )
        .unwrap();
        let mut tree = ShardTree::<_, 6, 3>::new(store, 4);
        let leaves = (1..=40u32)
            .map(|i| {
                (
                    format!("leaf-{i}"),
                    Retention::Checkpoint {
                        id: BlockHeight::from(i),
                        marking: if i % 4 == 0 {
                            Marking::Marked
                        } else {
                            Marking::None
                        },
                    },
                )
            })
            .collect::<Vec<_>>();
        tree.insert_frontier(
            Frontier::<String, 6>::empty(),
            Retention::Checkpoint {
                id: BlockHeight::from(0),
                marking: Marking::Reference,
            },
        )
        .unwrap();
        tree.batch_insert(Position::from(0), leaves.into_iter())
            .unwrap();
        assert_same_dump(&per_leaf, &dump_wallet_trees(&tree.store().conn));
    }
}
