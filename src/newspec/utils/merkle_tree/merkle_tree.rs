use plonky2::{
    hash::{hash_types::RichField, merkle_proofs::MerkleProof},
    plonk::config::Hasher,
};

use std::collections::HashMap;

#[derive(Debug)]
pub enum Node<F: RichField, H: Hasher<F>> {
    InnerNode { left: H::Hash, right: H::Hash },
    Leaf { value: Vec<F> },
}

impl<F: RichField, H: Hasher<F>> Node<F, H> {
    fn hash(&self) -> H::Hash {
        match self {
            Node::InnerNode { left, right } => H::two_to_one(left.clone(), right.clone()),
            Node::Leaf { value } => H::hash_or_noop(&value),
        }
    }
}

/// Sparse Merkle Tree which is compatible to the native plonky2 Merkle Tree.
#[derive(Debug)]
pub struct MerkleTree<F: RichField, H: Hasher<F>> {
    pub height: usize,
    pub nodes: HashMap<Vec<bool>, Node<F, H>>,
    zero: Vec<F>,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: Hasher<F>> MerkleTree<F, H> {
    pub fn new(height: usize, zero: Vec<F>) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let node = Node::Leaf::<F, H> {
            value: zero.clone(),
        };
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 0..height {
            let node = Node::InnerNode::<F, H> { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes: HashMap<Vec<bool>, Node<F, H>> = HashMap::new();

        Self {
            height,
            nodes,
            zero,
            zero_hashes,
        }
    }

    fn get_node_hash(&self, path: &Vec<bool>) -> H::Hash {
        assert!(path.len() <= self.height);
        match self.nodes.get(path) {
            Some(node) => node.hash(),
            None => self.zero_hashes[path.len()],
        }
    }

    fn get_sibling_hash(&self, path: &Vec<bool>) -> H::Hash {
        assert!(path.len() > 0);
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    pub fn get_root(&self) -> H::Hash {
        self.get_node_hash(&vec![])
    }

    pub fn get_leaf(&self, index: usize) -> Vec<F> {
        let path = &usize_to_vec(index, self.height);
        match self.nodes.get(path) {
            Some(Node::Leaf { value }) => value.clone(),
            Some(Node::InnerNode { left: _, right: _ }) => panic!(),
            None => self.zero.clone(),
        }
    }

    pub fn update(&mut self, index: usize, value: Vec<F>) {
        let mut path = usize_to_vec(index, self.height);

        self.nodes.insert(path.clone(), Node::Leaf { value });

        loop {
            let hash = self.get_node_hash(&path);
            let parent_path = path[0..path.len() - 1].to_vec();
            self.nodes.insert(
                parent_path,
                if path[path.len() - 1] {
                    Node::InnerNode {
                        left: self.get_sibling_hash(&path),
                        right: hash,
                    }
                } else {
                    Node::InnerNode {
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
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    #[test]
    fn tree_test() {
        let mut rng = rand::thread_rng();
        let height = 100;
        let default_leaf = vec![F::ZERO];
        let mut tree = MerkleTree::<F, H>::new(height, default_leaf);

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let new_leaf = F::rand_vec(4);
            tree.update(index, new_leaf.clone());
            let proof = tree.prove(index);
            assert_eq!(tree.get_leaf(index), new_leaf.clone());
            assert_eq!(tree.get_root(), get_merkle_root(index, &new_leaf, &proof));
            verify_merkle_proof(new_leaf, index, tree.get_root(), &proof).unwrap();
        }

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let leaf = tree.get_leaf(index);
            let proof = tree.prove(index);
            assert_eq!(tree.get_root(), get_merkle_root(index, &leaf, &proof));
            verify_merkle_proof(leaf, index, tree.get_root(), &proof).unwrap();
        }
    }
}
