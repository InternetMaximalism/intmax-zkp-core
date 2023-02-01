use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::{common::user_state::UserState, utils::merkle_tree::merkle_tree::MerkleTree};

pub struct WorldStateTree<F: RichField, H: Hasher<F>> {
    /// key: Address<F>
    // TODO: MerkleTree -> MerkleTreeTemplate
    pub merkle_tree: MerkleTree<F, H, UserState<F>>,
}
