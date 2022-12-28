use plonky2::{
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use serde::{Deserialize, Serialize};

use crate::sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut;

pub fn log2_ceil(value: usize) -> u32 {
    assert!(value != 0, "The first argument must be a positive number.");

    if value == 1 {
        return 0;
    }

    let mut log_value = 1;
    let mut tmp_value = value - 1;
    while tmp_value > 1 {
        tmp_value /= 2;
        log_value += 1;
    }

    log_value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "WrappedHashOut<F>: Deserialize<'de>"))]
pub struct MerkleProof<F: RichField> {
    pub index: usize,
    pub value: WrappedHashOut<F>,
    pub siblings: Vec<WrappedHashOut<F>>,
    pub root: WrappedHashOut<F>,
}

impl<F: RichField> MerkleProof<F> {
    pub fn new(depth: usize) -> Self {
        let index = Default::default();
        let value = Default::default();

        get_merkle_proof(&[value], index, depth)
    }
}

/// `2^depth` 個の leaf からなる Merkle tree に `leaves` で与えられた leaf を左から詰め,
/// 残りは `zero` で埋める. Merkle root と与えられた `index` に関する siblings を返す.
/// ただし, siblings は root から遠い順に並べる.
/// leaves に 1 つも leaf を与えなかったり, leaves の個数が 2 のべきでなかった場合,
/// もとの個数より小さくない最小の 2 のべきになるように `zero` を埋める.
/// Returns `(siblings, root)`
pub fn get_merkle_proof_with_zero<F: RichField>(
    leaves: &[WrappedHashOut<F>],
    index: usize,
    depth: usize,
    zero: WrappedHashOut<F>,
) -> MerkleProof<F> {
    let mut nodes = if leaves.is_empty() {
        vec![zero]
    } else {
        leaves.to_vec()
    };
    assert!(index < nodes.len());
    assert!(nodes.len() <= 1usize << depth);
    let num_leaves = nodes.len().next_power_of_two();
    let log_num_leaves = log2_ceil(num_leaves) as usize;
    let value = nodes[index];
    nodes.resize(num_leaves, zero);

    let mut siblings = vec![zero]; // initialize by zero hashes
    for _ in 1..depth {
        let last_zero: WrappedHashOut<F> = *siblings.last().unwrap();
        siblings.push(PoseidonHash::two_to_one(*last_zero, *last_zero).into());
    }

    let mut rest_index = index;
    for sibling in siblings.iter_mut().take(log_num_leaves) {
        let _ = std::mem::replace(sibling, nodes[rest_index ^ 1]); // XXX: out of index が起こる

        let mut new_nodes: Vec<WrappedHashOut<F>> = vec![];
        for j in 0..(nodes.len() / 2) {
            new_nodes.push(PoseidonHash::two_to_one(*nodes[2 * j], *nodes[2 * j + 1]).into());
        }

        rest_index >>= 1;
        nodes = new_nodes;
    }

    assert_eq!(nodes.len(), 1);
    let mut root = nodes[0];
    for sibling in siblings.iter().cloned().skip(log_num_leaves) {
        // log_num_leaves 層より上は sibling が必ず右側にくる.
        root = PoseidonHash::two_to_one(*root, *sibling).into();
    }

    MerkleProof {
        index,
        value,
        siblings,
        root,
    }
}

pub fn get_merkle_proof<F: RichField>(
    leaves: &[WrappedHashOut<F>],
    index: usize,
    depth: usize,
) -> MerkleProof<F> {
    get_merkle_proof_with_zero(leaves, index, depth, WrappedHashOut::ZERO)
}

/// 与えられた leaf `(index, value)` と `siblings` から Merkle root を計算する.
pub fn get_merkle_root<F: RichField>(
    index: usize,
    value: WrappedHashOut<F>,
    siblings: &[WrappedHashOut<F>],
) -> WrappedHashOut<F> {
    let mut root = value;
    let mut rest_index = index;
    for sibling in siblings {
        let (left, right) = if rest_index & 1 == 0 {
            (root, *sibling)
        } else {
            (*sibling, root)
        };
        root = PoseidonHash::two_to_one(*left, *right).into();
        rest_index >>= 1;
    }

    root
}

#[test]
fn test_get_block_hash_tree_proofs() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
    };

    type F = GoldilocksField;

    let mut leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| {
            HashOut {
                elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
            }
            .into()
        })
        .collect::<Vec<_>>();
    const N_LEVELS: usize = 10;
    let index = leaves.len() - 1;
    let MerkleProof {
        siblings,
        root: old_root,
        ..
    } = get_merkle_proof(&leaves, index, N_LEVELS);
    dbg!(old_root);

    // TODO: `index` 番目の要素が変化しても siblings は同じであることを確かめる.
    let new_leaf = HashOut {
        elements: [F::from_canonical_u32(50), F::ZERO, F::ZERO, F::ZERO],
    }
    .into();
    let new_root = get_merkle_root(index, new_leaf, &siblings);

    leaves[index] = new_leaf;
    let MerkleProof {
        siblings: actual_siblings,
        root: actual_new_root,
        ..
    } = get_merkle_proof(&leaves, index, N_LEVELS);
    assert_eq!(siblings, actual_siblings);
    assert_eq!(new_root, actual_new_root);
}

#[test]
#[should_panic]
fn test_get_block_hash_tree_proofs2() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
    };

    type F = GoldilocksField;

    let leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| {
            HashOut {
                elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
            }
            .into()
        })
        .collect::<Vec<_>>();
    const N_LEVELS: usize = 2;
    let index = leaves.len() - 1;
    get_merkle_proof(&leaves, index, N_LEVELS);
}
