use num::Integer;
use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::{AlgebraicHasher, GenericHashOut, Hasher},
    util::log2_ceil,
};
use serde::{Deserialize, Serialize};

pub trait KeyLike: Clone + Eq + std::fmt::Debug + Default + std::hash::Hash {
    /// little endian
    fn to_bits(&self) -> Vec<bool>;
}

pub trait ValueLike: Copy + PartialEq + std::fmt::Debug + Default {}

pub trait HashLike: Copy + PartialEq + std::fmt::Debug + Default {}

pub fn le_bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| {
            let mut byte = *byte;
            let mut res = vec![];
            for _ in 0..8 {
                res.push(byte.is_odd());
                byte >>= 1;
            }
            res
        })
        .collect::<Vec<_>>()
}

impl<F: RichField> KeyLike for HashOut<F> {
    fn to_bits(&self) -> Vec<bool> {
        let bytes = self.to_bytes();

        le_bytes_to_bits(&bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "H::Hash: Deserialize<'de>, K: Deserialize<'de>"))]
pub struct MerkleProof<F: RichField, H: Hasher<F>, K: Clone> {
    pub index: K,
    pub value: H::Hash,
    pub siblings: Vec<H::Hash>,
    pub root: H::Hash,
}

impl<F: RichField, H: AlgebraicHasher<F>> MerkleProof<F, H, usize> {
    pub fn new(depth: usize) -> Self {
        let index = Default::default();
        let value = Default::default();

        get_merkle_proof::<F, H>(&[value], index, depth)
    }
}

/// `2^depth` 個の leaf からなる Merkle tree に `leaves` で与えられた leaf を左から詰め,
/// 残りは `zero` で埋める. Merkle root と与えられた `index` に関する siblings を返す.
/// ただし, siblings は root から遠い順に並べる.
/// leaves に 1 つも leaf を与えなかったり, leaves の個数が 2 のべきでなかった場合,
/// もとの個数より小さくない最小の 2 のべきになるように `zero` を埋める.
/// Returns `(siblings, root)`
pub fn get_merkle_proof_with_zero<F: RichField, H: Hasher<F>>(
    leaves: &[H::Hash],
    index: usize,
    depth: usize,
    zero: H::Hash,
) -> MerkleProof<F, H, usize> {
    let mut nodes = if leaves.is_empty() {
        vec![zero]
    } else {
        leaves.to_vec()
    };
    assert!(index < nodes.len());
    assert!(nodes.len() <= 1usize << depth);
    let num_leaves = nodes.len().next_power_of_two();
    let log_num_leaves = log2_ceil(num_leaves);
    let value = nodes[index];
    nodes.resize(num_leaves, zero);

    let mut siblings = vec![zero]; // initialize by zero hashes
    for _ in 1..depth {
        let last_zero: H::Hash = *siblings.last().unwrap();
        siblings.push(H::two_to_one(last_zero, last_zero));
    }

    let mut rest_index = index;
    for sibling in siblings.iter_mut().take(log_num_leaves) {
        let _ = std::mem::replace(sibling, nodes[rest_index ^ 1]); // XXX: out of index が起こる

        let mut new_nodes: Vec<H::Hash> = vec![];
        for j in 0..(nodes.len() / 2) {
            new_nodes.push(H::two_to_one(nodes[2 * j], nodes[2 * j + 1]));
        }

        rest_index >>= 1;
        nodes = new_nodes;
    }

    assert_eq!(nodes.len(), 1);
    let mut root = nodes[0];
    for sibling in siblings.iter().cloned().skip(log_num_leaves) {
        // log_num_leaves 層より上は sibling が必ず右側にくる.
        root = H::two_to_one(root, sibling);
    }

    MerkleProof {
        index,
        value,
        siblings,
        root,
    }
}

pub fn get_merkle_proof<F: RichField, H: AlgebraicHasher<F>>(
    leaves: &[HashOut<F>],
    index: usize,
    depth: usize,
) -> MerkleProof<F, H, usize> {
    get_merkle_proof_with_zero(leaves, index, depth, HashOut::ZERO)
}

/// 与えられた leaf `(index, value)` と `siblings` から Merkle root を計算する.
pub fn get_merkle_root<F: RichField, H: Hasher<F>, K: KeyLike>(
    index: &K,
    value: H::Hash,
    siblings: &[H::Hash],
) -> H::Hash {
    let mut root = value;
    let mut index = index.to_bits();
    index.resize(siblings.len(), false);
    for (lr_bit, sibling) in index.iter().zip(siblings) {
        let (left, right) = if *lr_bit {
            (*sibling, root)
        } else {
            (root, *sibling)
        };
        root = H::two_to_one(left, right);
        // dbg!(left, right, root);
    }

    root
}

#[test]
fn test_get_block_hash_tree_proofs() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
    };

    type H = PoseidonHash;
    type F = GoldilocksField;

    let mut leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| HashOut {
            elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
        })
        .collect::<Vec<_>>();
    const N_LEVELS: usize = 10;
    let index = leaves.len() - 1;
    let MerkleProof {
        siblings,
        root: _old_root,
        ..
    } = get_merkle_proof::<F, H>(&leaves, index, N_LEVELS);

    // TODO: `index` 番目の要素が変化しても siblings は同じであることを確かめる.
    let new_leaf = HashOut {
        elements: [F::from_canonical_u32(50), F::ZERO, F::ZERO, F::ZERO],
    };
    let new_root = get_merkle_root::<_, PoseidonHash, _>(&index, new_leaf, &siblings);

    leaves[index] = new_leaf;
    let MerkleProof {
        siblings: actual_siblings,
        root: actual_new_root,
        ..
    } = get_merkle_proof::<F, H>(&leaves, index, N_LEVELS);
    assert_eq!(siblings, actual_siblings);
    assert_eq!(new_root, actual_new_root);
}

#[test]
#[should_panic]
fn test_get_block_hash_tree_proofs2() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
    };

    // type H = PoseidonHash;
    type F = GoldilocksField;

    let leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| HashOut {
            elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
        })
        .collect::<Vec<HashOut<F>>>();
    const N_LEVELS: usize = 2;
    let index = leaves.len() - 1;
    get_merkle_proof::<F, PoseidonHash>(&leaves, index, N_LEVELS);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "H::Hash: Deserialize<'de>, K: Deserialize<'de>"))]
pub struct MerkleProcessProof<F: RichField, H: Hasher<F>, K: Clone + std::fmt::Debug + Eq> {
    pub index: K,
    pub siblings: Vec<H::Hash>,
    pub old_value: H::Hash,
    pub new_value: H::Hash,
    pub old_root: H::Hash,
    pub new_root: H::Hash,
}
