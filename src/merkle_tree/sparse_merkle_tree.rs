use num::{BigUint, Integer, Zero};
use plonky2::{
    hash::{hash_types::RichField, merkle_proofs::MerkleProof},
    plonk::config::{AlgebraicHasher, Hasher},
};

use std::collections::HashMap;

use crate::{merkle_tree::tree::KeyLike, utils::hash::WrappedHashOut};

pub trait Leafable<F: RichField, H: Hasher<F>>: Clone + Default + Eq {
    fn hash(&self) -> H::Hash;
}

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for WrappedHashOut<F> {
    fn hash(&self) -> H::Hash {
        H::hash_or_noop(&self.elements)
    }
}

pub type MerklePath = Vec<bool>;

#[derive(Debug)]
pub struct SparseMerkleTreeMemory<F: RichField, H: Hasher<F>, V: Leafable<F, H>> {
    pub height: usize,
    pub nodes: HashMap<MerklePath, H::Hash>,
    pub leaves: HashMap<MerklePath, V>,
    zero_hashes: Vec<H::Hash>, // height + 1
}

impl<F: RichField, H: AlgebraicHasher<F>, V: Leafable<F, H>> SparseMerkleTreeMemory<F, H, V> {
    pub fn new(height: usize) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let node = V::default();
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 0..height {
            h = H::two_to_one(h, h);
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes = HashMap::new();
        let leaves = HashMap::new();

        Self {
            height,
            nodes,
            leaves,
            zero_hashes,
        }
    }

    /// partial_leaves を leaf に持つ tree を作る
    pub fn with_leaves(height: usize, partial_leaves: Vec<V>) -> Self {
        assert!(
            height as u32 >= usize::BITS || partial_leaves.len() <= 1 << height,
            "too many leaves"
        );
        let mut tree = Self::new(height);

        // TODO: 改善の余地あり
        for (index, leaf_data) in partial_leaves.into_iter().enumerate() {
            tree.update(&index, leaf_data);
        }

        tree
    }

    pub fn get_leaf_data<K: KeyLike>(&self, index: &K) -> V {
        let mut path = index.to_bits();
        path.resize(self.height, false);
        // assert_eq!(path.len(), self.height);
        path.reverse();
        match self.leaves.get(&path) {
            Some(data) => data.clone(),
            _ => V::default(),
        }
    }

    pub fn get_node_hash(&self, path: &MerklePath) -> H::Hash {
        assert!(path.len() <= self.height);
        match self.nodes.get(path) {
            Some(node) => *node,
            None => self.zero_hashes[path.len()],
        }
    }

    pub fn get_root(&self) -> H::Hash {
        self.get_node_hash(&vec![])
    }

    pub fn get_sibling_hash(&self, path: &MerklePath) -> H::Hash {
        assert!(!path.is_empty());
        // TODO maybe more elegant code exists
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];

        self.get_node_hash(&path)
    }

    pub fn update<K: KeyLike>(&mut self, index: &K, leaf_data: V) -> V {
        let mut path = index.to_bits();
        path.resize(self.height, false);
        // assert_eq!(path.len(), self.height);

        let mut path = path.clone();
        path.reverse();
        let old_leaf_data = self
            .leaves
            .insert(path.clone(), leaf_data.clone())
            .unwrap_or_default();
        let mut node_hash = leaf_data.hash();
        self.nodes.insert(path.clone(), node_hash);

        while !path.is_empty() {
            let sibling = self.get_sibling_hash(&path);

            // path の末尾を見ると同時に path を短くする.
            let lr_bit = path.pop().unwrap();
            node_hash = if lr_bit {
                H::two_to_one(sibling, node_hash)
            } else {
                H::two_to_one(node_hash, sibling)
            };
            self.nodes.insert(path.clone(), node_hash);
        }

        old_leaf_data
    }

    pub fn remove<K: KeyLike>(&mut self, index: &K) -> V {
        self.update(index, V::default())
    }

    pub fn insert<K: KeyLike>(&mut self, index: &K, leaf_data: V) -> anyhow::Result<()> {
        let old_leaf_data = self.update(index, leaf_data);
        anyhow::ensure!(
            old_leaf_data == V::default(),
            "specified index was already used"
        );

        Ok(())
    }

    pub fn prove(&self, path: &MerklePath) -> MerkleProof<F, H> {
        let mut path = path.clone();
        let mut siblings = vec![];
        while !path.is_empty() {
            siblings.push(self.get_sibling_hash(&path));
            path.pop();
        }

        // siblings.reverse();

        MerkleProof { siblings }
    }

    pub fn prove_leaf_node<K: KeyLike>(&self, index: &K) -> MerkleProof<F, H> {
        let mut path = index.to_bits();
        path.resize(self.height, false);
        // assert_eq!(path.len(), self.height);
        path.reverse();

        self.prove(&path)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node<F: RichField, H: Hasher<F>> {
    Inner { left: H::Hash, right: H::Hash },
    Leaf { data: Vec<F> },
}

impl<F: RichField, H: Hasher<F>> Node<F, H> {
    pub fn hash(&self) -> H::Hash {
        match self {
            Node::Inner { left, right } => H::two_to_one(*left, *right),
            Node::Leaf { data } => H::hash_or_noop(data),
        }
    }
}

impl KeyLike for usize {
    fn to_bits(&self) -> Vec<bool> {
        let mut x = *self;
        let mut v = vec![];
        loop {
            if x.is_zero() {
                break;
            }
            v.push(x.is_odd());
            x >>= 1;
        }

        v
    }
}

impl KeyLike for Vec<bool> {
    fn to_bits(&self) -> Vec<bool> {
        self.clone()
    }
}

impl KeyLike for BigUint {
    fn to_bits(&self) -> Vec<bool> {
        let mut x = self.clone();
        let mut v = vec![];
        loop {
            if x.is_zero() {
                break;
            }
            v.push(x.is_odd());
            x >>= 1;
        }

        v
    }
}

/// Verifies that the given leaf data is present at the given index in the Merkle tree with the
/// given root.
pub fn verify_merkle_proof<F: RichField, H: Hasher<F>, K: KeyLike, V: Leafable<F, H>>(
    leaf_data: V,
    leaf_index: &K,
    merkle_root: H::Hash,
    proof: &MerkleProof<F, H>,
) -> anyhow::Result<()> {
    let index = leaf_index.to_bits();
    let index_bits = &mut index.iter();
    let mut current_digest = leaf_data.hash();
    for &sibling_digest in proof.siblings.iter() {
        current_digest = if *index_bits.next().unwrap_or(&false) {
            H::two_to_one(sibling_digest, current_digest)
        } else {
            H::two_to_one(current_digest, sibling_digest)
        }
    }
    assert_eq!(current_digest, merkle_root, "Invalid Merkle proof.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::utils::hash::WrappedHashOut;

    use super::*;
    use num::BigUint;
    use plonky2::{
        hash::poseidon::PoseidonHash,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    #[test]
    fn test_merkle_inclusion_proof() {
        let mut rng = rand::thread_rng();
        let height = 256;
        // let zero = WrappedHashOut::default();
        let mut tree = SparseMerkleTreeMemory::<F, H, WrappedHashOut<F>>::new(height);

        let mut indices = vec![];
        for _ in 0..100 {
            let leaf_index = BigUint::from_bytes_le(&[(); 32].map(|_| rng.gen_range(0..=255)));
            let new_leaf_data = WrappedHashOut::rand();
            let _old_leaf = tree.update(&leaf_index, new_leaf_data);
            indices.push(leaf_index.clone());
            let proof = tree.prove_leaf_node(&leaf_index);
            assert_eq!(tree.get_leaf_data(&leaf_index), new_leaf_data.clone());
            verify_merkle_proof(new_leaf_data, &leaf_index, tree.get_root(), &proof).unwrap();
        }

        for _ in 0..50 {
            let leaf_index = &indices[rng.gen_range(0..100)];
            let leaf_data = tree.get_leaf_data(leaf_index);
            assert_ne!(leaf_data, WrappedHashOut::default());
            let proof = tree.prove_leaf_node(leaf_index);
            verify_merkle_proof(leaf_data, leaf_index, tree.get_root(), &proof).unwrap();
        }

        for _ in 0..50 {
            let leaf_index = BigUint::from_bytes_le(&[(); 32].map(|_| rng.gen_range(0..=255)));
            let leaf_data = tree.get_leaf_data(&leaf_index);
            let proof = tree.prove_leaf_node(&leaf_index);
            verify_merkle_proof(leaf_data, &leaf_index, tree.get_root(), &proof).unwrap();
        }

        for _ in 0..50 {
            let leaf_index = &indices[rng.gen_range(0..100)];
            tree.remove(leaf_index);
            let leaf_data = tree.get_leaf_data(leaf_index);
            let proof = tree.prove_leaf_node(leaf_index);
            verify_merkle_proof(leaf_data, leaf_index, tree.get_root(), &proof).unwrap();
        }
    }

    #[test]
    fn test_with_leaves() {
        let height = 256;
        let leaves = [(); 10].map(|_| WrappedHashOut::rand()).to_vec();
        let tree = SparseMerkleTreeMemory::<F, H, _>::with_leaves(height, leaves.clone());
        let actual_root = tree.get_root();

        let mut tree = SparseMerkleTreeMemory::<F, H, WrappedHashOut<F>>::new(height);
        for (index, leaf_data) in leaves.into_iter().enumerate() {
            tree.update(&index, leaf_data);
        }
        let expected_root = tree.get_root();
        assert_eq!(expected_root, actual_root);
    }
}
