# Compact-block trial decryption

`cargo bench -p zcash_client_backend --bench trial_decrypt` times two routines on a
fixed set of real mainnet compact blocks:

* `trial_decrypt_compact_block` — trial decryption only.
* `scan_block` — the full compact scan (trial decryption, nullifier matching, and
  note-commitment updates).

`notes/sec` is shielded outputs per second of trial decryption. A note is one
Sapling output, Orchard action, or Ironwood action. `decrypt share` is
trial-decryption time divided by `scan_block` wall time on the same blocks.
Both figures are the median of three passes after one warmup.

The viewing key is a fixed seed that does not own these notes. Almost every
output fails to decrypt, which is the cost a wallet pays while scanning.

## Fixture

Both ranges were fetched from the public lightwalletd at `zec.rocks` with
`GetBlockRange` and committed under `benches/fixtures/` (excluded from the
published crate). Each file is a sequence of little-endian `u32` lengths and
protobuf `CompactBlock` messages. The benchmark checks the SHA-256.

| Range | Heights | Mined (UTC) | Sapling | Orchard | Ironwood |
| --- | --- | --- | --- | --- | --- |
| Spam | 1,820,000–1,820,049 | 2022-09-24 16:30–17:32 | 39,245 | 3,554 | 0 |
| Ordinary | 3,530,000–3,530,049 | 2026-10-25 10:11–10:59 | 16 | 3 | 187 |

The spam range is inside the 2022–2023 sandblasting window. Block 1,820,000 was
mined on 2022-09-24; 33 of the 50 blocks contain a transaction with more than 50
shielded outputs. The ordinary range is outside that window.

`scripts/trial-decrypt-bench.sh` runs the benchmark at 1 core, half the logical
CPU count, and every core (`RAYON_NUM_THREADS`). The scanner this benchmark was
added against decrypts on the calling thread, so those three rows match until a
later change uses the rayon pool.

`decrypt share` is the ratio of two independent medians. When trial decryption
is essentially the whole scan, noise can put the ratio a fraction above 1.

## Baseline

Measured with the bench profile (release optimizations). The rows are
`RAYON_NUM_THREADS` of 1, 2, and 4. The three counts agree, because this
scanner does not use rayon.

| Change | Cores | Range | notes/sec | decrypt share of scan |
| --- | --- | --- | --- | --- |
| baseline | 1 | spam | 7321.4 | 101.4% |
| baseline | 2 | spam | 7519.1 | 99.5% |
| baseline | 4 | spam | 7646.2 | 99.9% |
| baseline | 1 | combined | 7503.0 | 98.5% |
| baseline | 2 | combined | 7469.1 | 99.7% |
| baseline | 4 | combined | 7639.1 | 99.7% |

The fixture copy that `scan_block` requires happens before the scan timer.
Ordinary blocks alone (206 notes) ran at about 8,600–9,100 notes/sec with the
same ~100% share. Later commits should append rows to this table.

## Parallel batch decryption

`parallel_try_compact_note_decryption` splits a top-level batch into one rayon
chunk per core once the batch has at least 32 outputs per chunk. A batch task
already running on the pool stays serial, and `BatchRunner::flush` is what
spreads that task across the pool instead. Ordinary blocks are below the
threshold, so they stay on one core.

| Change | Cores | Range | notes/sec | decrypt share of scan |
| --- | --- | --- | --- | --- |
| parallel chunks | 1 | spam | 7664.3 | 100.0% |
| parallel chunks | 2 | spam | 14196.8 | 99.8% |
| parallel chunks | 4 | spam | 28128.6 | 99.9% |
| parallel chunks | 1 | combined | 7660.5 | 100.1% |
| parallel chunks | 2 | combined | 14390.5 | 99.4% |
| parallel chunks | 4 | combined | 27917.0 | 99.3% |

Against the baseline at the same core count, the spam range is 1.05x at one
core (inside run-to-run noise), 1.89x at two cores, and 3.68x at four cores.
Ordinary blocks stay near 9,000 notes/sec at every core count because they are
below the split threshold.

## Orchard GLV key agreement

Upstream already provides this, and the numbers above include it.

`zcash_note_encryption` 0.5.1's `batch::try_compact_note_decryption` calls
`BatchDomain::batch_ka_agree_dec`. Orchard 0.16 implements that hook in
`orchard::note_encryption`: ephemeral keys are prepared with GLV endomorphism
windows for the whole batch (`PreparedEphemeralPublicKey::batch_tabled`, one
shared normalization), and each viewing key's scalar is decomposed once
(`pasta_curves::glv::Decomposed`) and reused for every ephemeral key. The
primitive is `pasta_curves::glv` (`Table`, `Decomposed`, `Table::mul_decomposed`),
added for this purpose in orchard 0.15.4. Shared secrets are the same bytes as
the per-output path.

Compact scan, the trial-decrypt benchmark, and `BatchRunner` all enter through
that batch API. There is no separate before/after for a local GLV change: the
baseline and the parallel rows already pay for one GLV ladder per
(viewing key, ephemeral key) instead of a generic variable-base multiply.
Reimplementing it here would fork orchard types. Sapling trial decryption still
uses Jubjub scalar multiplication from `sapling-crypto`, which has no GLV hook
in the dependency we link.

## Sandblast spam filter

`ScanOptions::spam_filter` is off by default. When set, trial decryption is
skipped for a transaction only when the network is mainnet, the block height
is in 1,710,000..=2,050,000, and the transaction has more than the threshold
number of shielded outputs (Sapling outputs + Orchard actions + Ironwood
actions). The default threshold is 50, so 51 or more are skipped and 50 are
still decrypted. Transparent outputs are not counted.

The window is the one ECC's wallet SDK used for sandblast batch sizing
(heights 1,710,000 to 2,050,000, late June 2022 through mid-April 2023;
<https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk/issues/1365>).
Block 1,710,000 was mined 2022-06-20. Block 2,050,000 was mined 2023-04-13,
just before zcashd 5.5.0's ZIP 317 block construction
(<https://zips.z.cash/zip-0317>). The Arborist sandblasting retrospective
dates the shielded spam from 15 June 2022 until that fee change
(<https://github.com/ZcashCommunityGrants/arboretum-notes/blob/main/AllArboristCallNotes/Sandblasting%20Retrospective%20-%20Summary.md>).

Outside that closed interval the filter does nothing, including on testnet
and regtest, so a later payroll transaction with many outputs is still
decrypted. Note commitments and nullifier matching still run for a filtered
transaction. A payment inside one is missed: the dust and a real note are
not distinguishable without trial decryption.

`TRIAL_DECRYPT_SPAM_FILTER=1` turns the filter on for the benchmark. The
spam fixture (heights 1,820,000–1,820,049) is inside the window. The ordinary
fixture is not, so its row matches the unfiltered run.

`notes/sec` still divides every shielded output in the fixture by the time
taken, including outputs the filter did not decrypt. The spam-range rate below
is that effective throughput. Almost all of those outputs sit in transactions
over the threshold, so the trial-decryption time falls from about 5.6s to
about 9ms. That is not a faster scalar multiplication.

| Change | Cores | Range | notes/sec | decrypt share of scan |
| --- | --- | --- | --- | --- |
| spam filter | 1 | spam | 4543015 | 64.7% |
| spam filter | 2 | spam | 4549486 | 65.0% |
| spam filter | 4 | spam | 4583089 | 65.0% |
| spam filter | 1 | ordinary | 9068 | 98.8% |
| spam filter | 4 | ordinary | 9104 | 99.6% |

The core count no longer matters on the spam range: the remaining outputs are
below the parallel-split threshold. The decrypt share falls because commitment
updates for the skipped outputs are now a visible fraction of the scan.
Ordinary blocks are outside the window and stay near 9,100 notes/sec.
