use std::collections::HashMap;

use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::{common::asset::Asset, utils::merkle_tree::merkle_tree::MerkleTree};

pub struct UserAssetTree<F: RichField, H: Hasher<F>> {
    pub merkle_tree: MerkleTree<F, H, Asset>,

    /// asset_id -> leaf_index
    pub asset_id_map: HashMap<usize, usize>,

    _max_leaf_index: usize,
}

impl<F: RichField, H: Hasher<F>> UserAssetTree<F, H> {
    pub fn new(height: usize) -> Self {
        Self {
            merkle_tree: MerkleTree::new(height),
            asset_id_map: HashMap::new(),
            _max_leaf_index: 0,
        }
    }
}
