use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use crate::newspec::utils::merkle_tree::merkle_tree::MerkleTree;

// TODO: rename to MergedTxHashTree
pub struct NullifierHashTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, HashOut<F>>,
}

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> NullifierHashTree<F, H> {
    pub fn new(height: usize) -> Self {
        Self {
            merkle_tree: MerkleTree::new(height),
        }
    }
}
