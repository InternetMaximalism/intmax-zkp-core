use num::{BigUint, Integer, Zero};
use plonky2::{
    hash::{hash_types::RichField, merkle_proofs::MerkleProof},
    plonk::config::Hasher,
};

use std::collections::HashMap;

use crate::merkle_tree::tree::KeyLike;

pub type MerklePath = Vec<bool>;

#[derive(Debug)]
pub struct SparseMerkleTreeMemory<F: RichField, H: Hasher<F>> {
    pub height: usize,
    pub nodes: HashMap<MerklePath, Node<F, H>>,
    pub zero: Vec<F>,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: Hasher<F>> SparseMerkleTreeMemory<F, H> {
    pub fn new(height: usize, zero: Vec<F>) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let node = Node::Leaf::<F, H> { data: zero.clone() };
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 0..height {
            let node = Node::Inner::<F, H> { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes: HashMap<MerklePath, Node<F, H>> = HashMap::new();

        Self {
            height,
            nodes,
            zero,
            zero_hashes,
        }
    }

    pub fn get_leaf_data<K: KeyLike>(&self, index: &K) -> Vec<F> {
        let mut path = index.to_bits();
        path.resize(self.height, false);
        // assert_eq!(path.len(), self.height);
        path.reverse();
        match self.nodes.get(&path) {
            Some(Node::Leaf { data }) => data.clone(),
            _ => self.zero.clone(),
        }
    }

    pub fn get_node_hash(&self, path: &MerklePath) -> H::Hash {
        assert!(path.len() <= self.height);
        match self.nodes.get(path) {
            Some(node) => node.hash(),
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

    pub fn update<K: KeyLike>(&mut self, index: &K, leaf_data: Vec<F>) -> Vec<F> {
        let mut path = index.to_bits();
        path.resize(self.height, false);
        // assert_eq!(path.len(), self.height);

        let mut path = path.clone();
        path.reverse();
        let old_leaf = self
            .nodes
            .insert(path.clone(), Node::Leaf { data: leaf_data });

        loop {
            let hash = self.get_node_hash(&path);
            let parent_path = path[0..path.len() - 1].to_vec();
            self.nodes.insert(
                parent_path.clone(),
                if path[path.len() - 1] {
                    Node::Inner {
                        left: self.get_sibling_hash(&path),
                        right: hash,
                    }
                } else {
                    Node::Inner {
                        left: hash,
                        right: self.get_sibling_hash(&path),
                    }
                },
            );
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }

        if let Some(Node::Leaf {
            data: old_leaf_data,
        }) = old_leaf
        {
            old_leaf_data
        } else {
            self.zero.clone()
        }
    }

    pub fn remove<K: KeyLike>(&mut self, index: &K) -> Vec<F> {
        self.update(index, self.zero.clone())
    }

    pub fn prove(&self, path: &MerklePath) -> MerkleProof<F, H> {
        let mut path = path.clone();
        let mut siblings = vec![];
        loop {
            siblings.push(self.get_sibling_hash(&path));
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
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
pub fn verify_merkle_proof<F: RichField, H: Hasher<F>, K: KeyLike>(
    leaf_data: Vec<F>,
    leaf_index: &K,
    merkle_root: H::Hash,
    proof: &MerkleProof<F, H>,
) -> anyhow::Result<()> {
    let index = leaf_index.to_bits();
    let index_bits = &mut index.iter();
    let mut current_digest = H::hash_or_noop(&leaf_data);
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
    use super::*;
    use num::BigUint;
    use plonky2::{
        field::types::{Field, Sample},
        hash::poseidon::PoseidonHash,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    // fn usize_to_vec(x: usize, length: usize) -> Vec<bool> {
    //     let mut x = x;
    //     let mut v = vec![];
    //     for _ in 0..length {
    //         v.push((x & 1) == 1);
    //         x >>= 1;
    //     }
    //     v.reverse();

    //     v
    // }

    #[test]
    fn test_merkle_inclusion_proof() {
        let mut rng = rand::thread_rng();
        let height = 256;
        let zero = vec![F::ZERO; 4];
        let mut tree = SparseMerkleTreeMemory::<F, H>::new(height, zero);

        let mut indices = vec![];
        for _ in 0..100 {
            let leaf_index = BigUint::from_bytes_le(&[(); 32].map(|_| rng.gen_range(0..=255)));
            let new_leaf_data = F::rand_vec(4);
            let old_leaf = tree.update(&leaf_index, new_leaf_data.clone());
            assert_eq!(old_leaf, tree.zero);
            indices.push(leaf_index.clone());
            let proof = tree.prove_leaf_node(&leaf_index);
            assert_eq!(tree.get_leaf_data(&leaf_index), new_leaf_data.clone());
            verify_merkle_proof(new_leaf_data, &leaf_index, tree.get_root(), &proof).unwrap();
        }

        for _ in 0..50 {
            let leaf_index = &indices[rng.gen_range(0..100)];
            let leaf_data = tree.get_leaf_data(leaf_index);
            assert_ne!(leaf_data, tree.zero);
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
}
