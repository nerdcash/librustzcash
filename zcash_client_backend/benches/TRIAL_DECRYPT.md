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

`scripts/trial-decrypt-bench.sh` runs the benchmark at 1 core, half the host, and
every core (`RAYON_NUM_THREADS`). The scanner this benchmark was added against
decrypts on the calling thread, so those three rows match until a later change
uses the rayon pool.

`decrypt share` is the ratio of two independent medians. When trial decryption
is essentially the whole scan, noise can put the ratio a fraction above 1.

## Baseline

Measured on the bench profile (release optimizations) of this commit, on a
4-core x86_64 host. N is half the host, 2 cores. The three core counts agree,
because this scanner does not use rayon.

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
