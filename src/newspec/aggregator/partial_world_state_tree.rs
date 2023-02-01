use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use crate::newspec::utils::merkle_tree::merkle_tree::MerkleTree;

pub struct PartialWorldStateTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, HashOut<F>>,
}
