use std::collections::HashMap;

use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::{
    common::asset::{Asset, TokenKind},
    utils::merkle_tree::merkle_tree::MerkleTree,
};

pub struct UserAssetTree<F: RichField, H: Hasher<F>> {
    pub merkle_tree: MerkleTree<F, H, Asset<F>>,
    pub token_index_map: HashMap<TokenKind<F>, usize>,
    max_token_index: usize,
}
