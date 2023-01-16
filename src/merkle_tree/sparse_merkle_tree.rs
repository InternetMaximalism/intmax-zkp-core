use plonky2::{
    hash::{hash_types::RichField, merkle_proofs::MerkleProof},
    plonk::config::Hasher,
};

use std::collections::HashMap;

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

    pub fn get_leaf_data(&self, path: &MerklePath) -> Vec<F> {
        assert_eq!(path.len(), self.height);
        match self.nodes.get(path) {
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

    pub fn update(&mut self, path: &MerklePath, leaf_data: Vec<F>) {
        assert_eq!(path.len(), self.height);
        self.nodes
            .insert(path.clone(), Node::Leaf { data: leaf_data });

        let mut path = path.clone();
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
    }

    pub fn prove(&self, path: &MerklePath) -> MerkleProof<F, H> {
        assert_eq!(path.len(), self.height);
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

        MerkleProof { siblings }
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

    #[test]
    fn test_merkle_inclusion_proof() {
        let mut rng = rand::thread_rng();
        let height = 30;
        let zero = vec![F::ZERO; 4];
        let mut tree = SparseMerkleTreeMemory::<F, H>::new(height, zero);

        for _ in 0..100 {
            let leaf_index = rng.gen_range(0..1 << height);
            let path = usize_to_vec(leaf_index, height);
            let new_leaf_data = F::rand_vec(4);
            tree.update(&path, new_leaf_data.clone());
            let proof = tree.prove(&path);
            assert_eq!(tree.get_leaf_data(&path), new_leaf_data.clone());
            verify_merkle_proof(new_leaf_data, leaf_index, tree.get_root(), &proof).unwrap();
        }

        for _ in 0..100 {
            let leaf_index = rng.gen_range(0..1 << height);
            let path = usize_to_vec(leaf_index, height);
            let leaf_data = tree.get_leaf_data(&path);
            let proof = tree.prove(&path);
            verify_merkle_proof(leaf_data, leaf_index, tree.get_root(), &proof).unwrap();
        }
    }
}
