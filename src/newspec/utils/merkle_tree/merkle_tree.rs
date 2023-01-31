use plonky2::{
    hash::{hash_types::RichField, merkle_proofs::MerkleProof},
    plonk::config::Hasher,
};

use std::collections::HashMap;

use crate::newspec::common::traits::Leafable;

/// Sparse Merkle Tree which is compatible to the native plonky2 Merkle Tree.
#[derive(Debug)]
pub struct MerkleTree<F: RichField, H: Hasher<F>, V: Leafable<F, H>> {
    height: usize,
    node_hashes: HashMap<Vec<bool>, H::Hash>,
    leaves: HashMap<usize, V>,
    zero: V,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: Hasher<F>, V: Leafable<F, H>> MerkleTree<F, H, V> {
    pub fn new(height: usize, zero: V) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let mut h = V::default_hash();
        zero_hashes.push(h);
        for _ in 0..height {
            h = H::two_to_one(h, h);
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let node_hashes: HashMap<Vec<bool>, H::Hash> = HashMap::new();
        let leaves: HashMap<usize, V> = HashMap::new();

        Self {
            height,
            node_hashes,
            leaves,
            zero,
            zero_hashes,
        }
    }

    fn get_node_hash(&self, path: &Vec<bool>) -> H::Hash {
        assert!(path.len() <= self.height);
        match self.node_hashes.get(path) {
            Some(h) => *h,
            None => self.zero_hashes[path.len()],
        }
    }

    fn get_sibling_hash(&self, path: &Vec<bool>) -> H::Hash {
        assert!(!path.is_empty());
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    pub fn get_root(&self) -> H::Hash {
        self.get_node_hash(&vec![])
    }

    pub fn get_leaf(&self, index: usize) -> Option<V> {
        self.leaves.get(&index).cloned()
    }

    pub fn update(&mut self, index: usize, leaf: V) {
        let mut path = usize_to_vec(index, self.height);

        self.leaves.insert(index, leaf.clone());
        self.node_hashes.insert(path.clone(), leaf.hash());

        let mut h = leaf.hash();

        while !path.is_empty() {
            let sibling = self.get_sibling_hash(&path);
            h = if path.pop().unwrap() {
                H::two_to_one(sibling, h)
            } else {
                H::two_to_one(h, sibling)
            };
            self.node_hashes.insert(path.clone(), h);
        }
    }

    pub fn remove(&mut self, index: usize) {
        self.update(index, self.zero.clone())
    }

    pub fn prove(&self, index: usize) -> MerkleProof<F, H> {
        let mut path = usize_to_vec(index, self.height);
        let mut siblings = vec![];
        loop {
            siblings.push(self.get_sibling_hash(&path));
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
        MerkleProof { siblings }
    }
}

/// usize to big endian bool vec.
fn usize_to_vec(x: usize, length: usize) -> Vec<bool> {
    let mut x = x;
    let mut v = vec![];
    for _ in 0..length {
        v.push((x & 1) == 1);
        x >>= 1;
    }
    v.reverse();
    v
}

pub fn get_merkle_root<F: RichField, H: Hasher<F>>(
    index: usize,
    leaf_data: &Vec<F>,
    proof: &MerkleProof<F, H>,
) -> H::Hash {
    let mut index = index;
    let mut current_digest = H::hash_or_noop(leaf_data);
    for &sibling_digest in proof.siblings.iter() {
        let bit = index & 1;
        index >>= 1;
        current_digest = if bit == 1 {
            H::two_to_one(sibling_digest, current_digest)
        } else {
            H::two_to_one(current_digest, sibling_digest)
        }
    }
    current_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::types::{Field, Sample},
        hash::{merkle_proofs::verify_merkle_proof, poseidon::PoseidonHash},
        plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;
    type V = Vec<F>;

    impl<F: RichField, H: Hasher<F>> Leafable<F, H> for V {
        /// Default hash which indicates empty value.
        fn default_hash() -> H::Hash {
            H::hash_no_pad(&[])
        }

        /// Hash of its value.
        fn hash(&self) -> H::Hash {
            H::hash_no_pad(self)
        }
    }

    #[test]
    fn tree_test() {
        let mut rng = rand::thread_rng();
        let height = 100;
        let default_leaf = vec![F::ZERO];
        let mut tree = MerkleTree::<F, H, V>::new(height, default_leaf);

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let new_leaf = F::rand_vec(4);
            tree.update(index, new_leaf.clone());
            let proof = tree.prove(index);
            assert_eq!(tree.get_leaf(index).unwrap(), new_leaf.clone());
            assert_eq!(tree.get_root(), get_merkle_root(index, &new_leaf, &proof));
            verify_merkle_proof(new_leaf, index, tree.get_root(), &proof).unwrap();
        }

        // for _ in 0..100 {
        //     let index = rng.gen_range(0..1 << height);
        //     let leaf = tree.get_leaf(index);
        //     let proof = tree.prove(index);
        //     assert_eq!(tree.get_root(), get_merkle_root(index, &leaf, &proof));
        //     verify_merkle_proof(leaf, index, tree.get_root(), &proof).unwrap();
        // }
    }
}
