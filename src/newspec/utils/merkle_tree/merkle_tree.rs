use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::{verify_merkle_proof, MerkleProof, MerkleProofTarget},
    },
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use std::collections::HashMap;

use crate::newspec::common::traits::{Leafable, LeafableTarget};

/// Sparse Merkle Tree which is compatible to the native plonky2 Merkle Tree.
#[derive(Debug)]
pub struct MerkleTree<F: RichField, H: Hasher<F>, V: Leafable<F, H>> {
    height: usize,
    node_hashes: HashMap<Vec<bool>, H::Hash>,
    leaves: HashMap<usize, V>,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: Hasher<F>, V: Leafable<F, H>> MerkleTree<F, H, V> {
    pub fn new(height: usize) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let mut h = V::empty_leaf().hash();
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

    pub fn get_leaf(&self, index: usize) -> V {
        match self.leaves.get(&index) {
            Some(leaf) => leaf.clone(),
            None => V::empty_leaf(),
        }
    }

    pub fn update(&mut self, index: usize, leaf: V) {
        let mut path = usize_to_vec(index, self.height);

        self.leaves.insert(index, leaf.clone());

        let mut h = leaf.hash();
        self.node_hashes.insert(path.clone(), h);

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
        self.update(index, V::empty_leaf())
    }

    pub fn prove(&self, index: usize) -> MerkleProof<F, H> {
        let mut path = usize_to_vec(index, self.height);
        let mut siblings = vec![];
        while !path.is_empty() {
            siblings.push(self.get_sibling_hash(&path));
            path.pop();
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

pub fn get_merkle_root<F: RichField, H: Hasher<F>, V: Leafable<F, H>>(
    index: usize,
    leaf: &V,
    proof: &MerkleProof<F, H>,
) -> H::Hash {
    let mut index = index;
    let mut current_digest = leaf.hash();
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

pub fn verify_merkle_proof_with_leaf<
    F: RichField,
    H: Hasher<F, Hash = HashOut<F>>,
    V: Leafable<F, H>,
>(
    leaf_data: V,
    leaf_index: usize,
    merkle_root: H::Hash,
    proof: &MerkleProof<F, H>,
) -> anyhow::Result<()> {
    verify_merkle_proof(
        leaf_data.hash().elements.to_vec(),
        leaf_index,
        merkle_root,
        proof,
    )
}

pub fn verify_merkle_proof_with_leaf_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    VT: LeafableTarget<F, H, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_data: VT,
    leaf_index: Target,
    merkle_root: HashOutTarget,
    proof: &MerkleProofTarget,
) {
    let index_bits = builder.split_le(leaf_index, proof.siblings.len());
    let leaf_hash = leaf_data.hash(builder).elements.to_vec();
    builder.verify_merkle_proof::<H>(leaf_hash, &index_bits, merkle_root, proof);
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::types::Sample,
        hash::poseidon::PoseidonHash,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;
    type V = Vec<F>;

    impl<F: RichField, H: Hasher<F>> Leafable<F, H> for Vec<F> {
        /// Default hash which indicates empty value.
        fn empty_leaf() -> Self {
            vec![]
        }
        /// Hash of its value.
        fn hash(&self) -> H::Hash {
            H::hash_no_pad(self)
        }
    }

    #[test]
    fn test_merkle_tree() {
        let mut rng = rand::thread_rng();
        let height = 10;

        let mut tree = MerkleTree::<F, H, V>::new(height);

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let new_leaf = F::rand_vec(4);
            tree.update(index, new_leaf.clone());
        }

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let leaf = tree.get_leaf(index);
            let proof = tree.prove(index);
            assert_eq!(tree.get_leaf(index), leaf.clone());
            assert_eq!(tree.get_root(), get_merkle_root(index, &leaf, &proof));
            let h = Leafable::<F, H>::hash(&leaf);
            verify_merkle_proof_with_leaf(h, index, tree.get_root(), &proof).unwrap();
            verify_merkle_proof_with_leaf(leaf, index, tree.get_root(), &proof).unwrap();
        }
    }
}
