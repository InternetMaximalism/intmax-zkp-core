use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::{
    common::transaction::WithdrawTransaction, utils::merkle_tree::merkle_tree::MerkleTree,
};

// Notice: Solidity friendly な hash を用いる必要がある.
pub struct WithdrawTree<F: RichField, H: Hasher<F>> {
    pub merkle_tree: MerkleTree<F, H, WithdrawTransaction>,
}
