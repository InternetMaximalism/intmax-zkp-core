use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use crate::newspec::{
    common::transaction::DepositTransaction, utils::merkle_tree::merkle_tree::MerkleTree,
};

// Notice: Solidity friendly な hash を用いる必要がある.
pub struct DepositTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, DepositTransaction>,
}
