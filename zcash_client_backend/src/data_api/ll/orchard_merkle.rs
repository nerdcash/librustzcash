//! Orchard note-commitment hashing with the Sinsemilla generators cached.
//!
//! [`orchard::tree::MerkleHashOrchard::combine`] rebuilds each of the 1,024 Sinsemilla
//! generators with a curve-equation check. Those points are constant, so this module validates
//! them once and reuses the affine points. The message layout, the incomplete-addition rules, and
//! the extracted digest match `combine`. Pairs at one level are independent and are hashed in
//! parallel; the final coordinate extraction is one batched inversion.

use std::sync::OnceLock;

use group::ff::{Field, PrimeField};
use group::{Curve, Group};
use incrementalmerkletree::Level;
use orchard::tree::MerkleHashOrchard;
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;
use rayon::prelude::*;
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};

/// Domain separator for $\mathsf{MerkleCRH^{Orchard}}$.
const MERKLE_CRH_PERSONALIZATION: &[u8] = b"z.cash:Orchard-MerkleCRH";

const K: usize = sinsemilla::K;
/// $\ell^\mathsf{Orchard}_\mathsf{Merkle}$, the bit length of a Pallas base field element.
const MERKLE_BITS: usize = 255;
const MESSAGE_BITS: usize = K + MERKLE_BITS + MERKLE_BITS;

fn generator_table() -> &'static [pallas::Affine; 1 << K] {
    static TABLE: OnceLock<[pallas::Affine; 1 << K]> = OnceLock::new();
    TABLE.get_or_init(|| {
        std::array::from_fn(|index| {
            let (x, y) = sinsemilla::SINSEMILLA_S[index];
            Option::from(pallas::Affine::from_xy(x, y))
                .expect("Sinsemilla S generator is on the curve")
        })
    })
}

fn domain_q() -> pallas::Point {
    static Q: OnceLock<pallas::Point> = OnceLock::new();
    *Q.get_or_init(|| {
        pallas::Point::hash_to_curve(sinsemilla::Q_PERSONALIZATION)(MERKLE_CRH_PERSONALIZATION)
    })
}

fn le_bits_10(value: usize) -> [bool; K] {
    let mut bits = [false; K];
    for (bit, slot) in bits.iter_mut().enumerate() {
        *slot = (value >> bit) & 1 == 1;
    }
    bits
}

fn field_bits(bytes: &[u8; 32]) -> [bool; MERKLE_BITS] {
    let mut bits = [false; MERKLE_BITS];
    for (bit, slot) in bits.iter_mut().enumerate() {
        *slot = (bytes[bit / 8] >> (bit % 8)) & 1 == 1;
    }
    bits
}

/// Incomplete mixed addition, matching `sinsemilla`'s `IncompletePoint + Affine`.
fn incomplete_mixed(point: pallas::Point, affine: pallas::Affine) -> CtOption<pallas::Point> {
    let other = group::CurveAffine::to_curve(&affine);
    CtOption::new(
        point + affine,
        !(point.is_identity() | other.is_identity() | point.ct_eq(&other) | point.ct_eq(&-other)),
    )
}

fn incomplete_add(left: pallas::Point, right: pallas::Point) -> CtOption<pallas::Point> {
    CtOption::new(
        left + right,
        !(left.is_identity() | right.is_identity() | left.ct_eq(&right) | left.ct_eq(&-right)),
    )
}

struct HashedPoint {
    point: pallas::Point,
    valid: subtle::Choice,
}

fn hash_to_point(
    q: pallas::Point,
    generators: &[pallas::Affine; 1 << K],
    level: u8,
    left: &MerkleHashOrchard,
    right: &MerkleHashOrchard,
) -> HashedPoint {
    let mut message = [false; MESSAGE_BITS];
    message[..K].copy_from_slice(&le_bits_10(usize::from(level)));
    message[K..K + MERKLE_BITS].copy_from_slice(&field_bits(&left.to_bytes()));
    message[K + MERKLE_BITS..].copy_from_slice(&field_bits(&right.to_bytes()));

    let mut acc = CtOption::new(q, 1.into());
    // `MESSAGE_BITS` is a multiple of `K`, so Sinsemilla's padding step adds no bits.
    let (chunks, remainder) = message.as_chunks::<K>();
    debug_assert!(remainder.is_empty());
    for chunk in chunks {
        let mut index = 0usize;
        for (bit, flag) in chunk.iter().enumerate() {
            if *flag {
                index |= 1 << bit;
            }
        }
        let generator = generators[index];
        acc = acc.and_then(|point| {
            incomplete_mixed(point, generator).and_then(|sum| incomplete_add(sum, point))
        });
    }

    // `MESSAGE_BITS` is a multiple of `K`, so the padding step of SinsemillaHashToPoint adds
    // nothing. `into_option` is not required: a rejected sum stays `None` and becomes the zero
    // digest, matching `combine`.
    match Option::from(acc) {
        Some(point) => HashedPoint {
            point,
            valid: 1.into(),
        },
        None => HashedPoint {
            point: pallas::Point::identity(),
            valid: 0.into(),
        },
    }
}

fn zero_digest() -> MerkleHashOrchard {
    Option::from(MerkleHashOrchard::from_bytes(&[0; 32])).expect("zero is a canonical Pallas base")
}

fn digest(point: &pallas::Affine, valid: subtle::Choice) -> MerkleHashOrchard {
    let x = Option::from(point.coordinates().map(|coordinates| *coordinates.x()))
        .unwrap_or(pallas::Base::ZERO);
    let parsed =
        Option::from(MerkleHashOrchard::from_bytes(&x.to_repr())).unwrap_or_else(zero_digest);
    MerkleHashOrchard::conditional_select(&zero_digest(), &parsed, valid)
}

/// Hash every pair at `level`, in input order.
pub(super) fn combine_merkle_batch<'a>(
    level: Level,
    pairs: impl IntoIterator<Item = (&'a MerkleHashOrchard, &'a MerkleHashOrchard)>,
) -> Vec<MerkleHashOrchard> {
    let pairs = pairs.into_iter().collect::<Vec<_>>();
    if pairs.is_empty() {
        return Vec::new();
    }
    let q = domain_q();
    let generators = generator_table();
    let level = u8::from(level);
    let hashed = pairs
        .par_iter()
        .map(|(left, right)| hash_to_point(q, generators, level, left, right))
        .collect::<Vec<_>>();
    let mut affine = vec![pallas::Affine::default(); hashed.len()];
    pallas::Point::batch_normalize(
        &hashed.iter().map(|hashed| hashed.point).collect::<Vec<_>>(),
        &mut affine,
    );
    hashed
        .iter()
        .zip(affine.iter())
        .map(|(hashed, point)| digest(point, hashed.valid))
        .collect()
}
