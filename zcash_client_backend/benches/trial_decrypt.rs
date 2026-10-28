//! Trial decryption over a fixed set of real mainnet compact blocks.
//!
//! The fixture is two contiguous ranges fetched from `zec.rocks` (lightwalletd
//! `GetBlockRange`) and checked into `benches/fixtures/`:
//!
//! * `mainnet-1820000-1820049.pb` — heights 1_820_000..=1_820_049, mined
//!   2022-09-24. This sits inside the sandblasting window (see the benchmark
//!   notes). 39_245 Sapling outputs and 3_554 Orchard actions, 33 transactions
//!   with more than 50 shielded outputs.
//! * `mainnet-3530000-3530049.pb` — heights 3_530_000..=3_530_049, mined
//!   2026-10-25, outside that window. Ordinary traffic: 16 Sapling outputs,
//!   3 Orchard actions, 187 Ironwood actions.
//!
//! Each record is a little-endian `u32` length followed by a protobuf
//! `CompactBlock`. SHA-256 of each file is checked before use.
//!
//! Run all three core counts with `scripts/trial-decrypt-bench.sh`. A single
//! `cargo bench -p zcash_client_backend --bench trial_decrypt` measures whatever
//! `RAYON_NUM_THREADS` selects (or every core, when that variable is unset).
//! The baseline scanner does not consult the rayon pool, so the three counts
//! match until trial decryption is parallelized.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use prost::Message;
use sha2::{Digest, Sha256};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::scanning::{
    ScanOptions, ScanningKeys, SpamFilter, SpendIdentifiers, scan_block_with_options,
    trial_decrypt_compact_block_with_options,
};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::MAIN_NETWORK;
use zip32::AccountId;

struct Fixture {
    label: &'static str,
    file: &'static str,
    sha256: &'static str,
    first_height: u64,
    last_height: u64,
    sapling: usize,
    orchard: usize,
    ironwood: usize,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        label: "spam-1820000-1820049",
        file: "mainnet-1820000-1820049.pb",
        sha256: "cab4b8a02d81d1af05a2e8fd0b9f8e3fd559bef1eac07697ab7ccf608c6c1ba6",
        first_height: 1_820_000,
        last_height: 1_820_049,
        sapling: 39_245,
        orchard: 3_554,
        ironwood: 0,
    },
    Fixture {
        label: "ordinary-3530000-3530049",
        file: "mainnet-3530000-3530049.pb",
        sha256: "544f35365ea9b9c56b78e30bd4d56549012d3849b94b86beca564809e24a4400",
        first_height: 3_530_000,
        last_height: 3_530_049,
        sapling: 16,
        orchard: 3,
        ironwood: 187,
    },
];

struct Range {
    label: String,
    blocks: Vec<CompactBlock>,
    notes: u64,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benches/fixtures")
        .join(name)
}

fn load_fixture(fixture: &Fixture) -> Range {
    let path = fixture_path(fixture.file);
    let bytes = std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "reading {}: {err}. These fixtures are committed under benches/fixtures and excluded from the published crate.",
            path.display()
        )
    });
    let digest = hex_sha256(&Sha256::digest(&bytes));
    assert_eq!(
        digest, fixture.sha256,
        "fixture {} hash mismatch",
        fixture.file
    );

    let mut rest = bytes.as_slice();
    let mut blocks = Vec::new();
    while !rest.is_empty() {
        assert!(
            rest.len() >= 4,
            "truncated length prefix in {}",
            fixture.file
        );
        let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        rest = &rest[4..];
        assert!(
            rest.len() >= len,
            "truncated compact block in {}",
            fixture.file
        );
        let block = CompactBlock::decode(&rest[..len])
            .unwrap_or_else(|err| panic!("decode {}: {err}", fixture.file));
        rest = &rest[len..];
        blocks.push(block);
    }

    assert_eq!(blocks.len(), 50, "{}", fixture.file);
    assert_eq!(blocks.first().unwrap().height, fixture.first_height);
    assert_eq!(blocks.last().unwrap().height, fixture.last_height);
    for pair in blocks.windows(2) {
        assert_eq!(pair[1].height, pair[0].height + 1);
    }

    let mut sapling = 0usize;
    let mut orchard = 0usize;
    let mut ironwood = 0usize;
    for block in &blocks {
        for tx in &block.vtx {
            sapling += tx.outputs.len();
            orchard += tx.actions.len();
            ironwood += tx.ironwood_actions.len();
        }
    }
    assert_eq!(sapling, fixture.sapling, "{}", fixture.label);
    assert_eq!(orchard, fixture.orchard, "{}", fixture.label);
    assert_eq!(ironwood, fixture.ironwood, "{}", fixture.label);

    Range {
        label: fixture.label.to_string(),
        notes: (sapling + orchard + ironwood) as u64,
        blocks,
    }
}

fn hex_sha256(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn thread_count() -> usize {
    match std::env::var("RAYON_NUM_THREADS") {
        Ok(value) => value.parse::<usize>().expect("RAYON_NUM_THREADS"),
        Err(_) => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
    }
}

fn scanning_keys() -> ScanningKeys<u32, (u32, zip32::Scope)> {
    // A fixed key that does not own these notes. Trial decryption of outputs
    // that are not ours is the cost a wallet pays on every shielded output.
    let seed = [0x5a_u8; 64];
    let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, AccountId::ZERO)
        .expect("seed derives a unified spending key");
    ScanningKeys::from_account_ufvks([(0u32, usk.to_unified_full_viewing_key())])
}

fn scan_options() -> ScanOptions {
    match std::env::var("TRIAL_DECRYPT_SPAM_FILTER") {
        Ok(value) if value == "1" => ScanOptions::default().spam_filter(SpamFilter::default()),
        _ => ScanOptions::default(),
    }
}

fn time_decrypt(
    keys: &ScanningKeys<u32, (u32, zip32::Scope)>,
    blocks: &[CompactBlock],
    options: &ScanOptions,
) -> u128 {
    let start = Instant::now();
    let mut decrypted = 0usize;
    for block in blocks {
        decrypted += trial_decrypt_compact_block_with_options(&MAIN_NETWORK, block, keys, options)
            .unwrap_or_else(|err| panic!("trial decrypt at height {}: {err}", block.height));
    }
    black_box(decrypted);
    start.elapsed().as_nanos()
}

fn time_scan(
    keys: &ScanningKeys<u32, (u32, zip32::Scope)>,
    blocks: &[CompactBlock],
    options: &ScanOptions,
) -> u128 {
    // `scan_block` takes ownership. Copy the protobufs before the timer so
    // `scan_ns` is the scan itself, not the fixture clone. Trial decryption
    // borrows the same blocks.
    let owned: Vec<CompactBlock> = blocks.to_vec();
    let spends = SpendIdentifiers::empty();
    let start = Instant::now();
    let mut txs = 0usize;
    for block in owned {
        let height = block.height;
        let scanned = scan_block_with_options::<_, _, _, std::convert::Infallible>(
            &MAIN_NETWORK,
            block,
            keys,
            &spends,
            None,
            *options,
            #[cfg(feature = "transparent-inputs")]
            |_addr| Ok(None),
        )
        .unwrap_or_else(|err| panic!("scan_block at height {height}: {err}"));
        txs += scanned.transactions().len();
    }
    black_box(txs);
    start.elapsed().as_nanos()
}

fn median(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

struct Sample {
    decrypt_ns: u128,
    scan_ns: u128,
}

fn measure(
    keys: &ScanningKeys<u32, (u32, zip32::Scope)>,
    blocks: &[CompactBlock],
    options: &ScanOptions,
) -> Sample {
    // The first pass pays for key schedule setup and page faults.
    black_box(time_decrypt(keys, blocks, options));
    black_box(time_scan(keys, blocks, options));

    let mut decrypt_ns = [0u128; 3];
    let mut scan_ns = [0u128; 3];
    for i in 0..3 {
        decrypt_ns[i] = time_decrypt(keys, blocks, options);
        scan_ns[i] = time_scan(keys, blocks, options);
    }
    Sample {
        decrypt_ns: median(&mut decrypt_ns),
        scan_ns: median(&mut scan_ns),
    }
}

fn emit(threads: usize, label: &str, notes: u64, sample: &Sample) {
    let notes_per_sec = if sample.decrypt_ns == 0 {
        0.0
    } else {
        (notes as f64) * 1_000_000_000.0 / (sample.decrypt_ns as f64)
    };
    let share = if sample.scan_ns == 0 {
        0.0
    } else {
        (sample.decrypt_ns as f64) / (sample.scan_ns as f64)
    };
    // Stable line for scripts/trial-decrypt-bench.sh. `notes_per_sec` is the
    // trial-decryption rate. `decrypt_share` is trial-decryption time divided
    // by `scan_block` wall time on the same blocks.
    println!(
        "TRIAL_DECRYPT threads={threads} range={label} notes={notes} decrypt_ns={} scan_ns={} notes_per_sec={notes_per_sec:.1} decrypt_share={share:.6}",
        sample.decrypt_ns, sample.scan_ns
    );
}

fn main() {
    let threads = thread_count();
    let keys = scanning_keys();
    let options = scan_options();
    let suffix = if options.spam_filter.is_some() {
        "+spam-filter"
    } else {
        ""
    };
    let ranges: Vec<Range> = FIXTURES.iter().map(load_fixture).collect();

    let mut combined_blocks = Vec::new();
    let mut combined_notes = 0u64;
    let mut samples = Vec::new();
    for range in &ranges {
        let sample = measure(&keys, &range.blocks, &options);
        emit(
            threads,
            &format!("{}{suffix}", range.label),
            range.notes,
            &sample,
        );
        combined_blocks.extend(range.blocks.iter().cloned());
        combined_notes += range.notes;
        samples.push(sample);
    }

    // Combined is measured as its own pass so the ratio is not a sum of
    // independently warmed ranges.
    let combined = measure(&keys, &combined_blocks, &options);
    emit(
        threads,
        &format!("combined{suffix}"),
        combined_notes,
        &combined,
    );
    black_box(samples);
}
