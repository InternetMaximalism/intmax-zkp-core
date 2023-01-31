use std::collections::HashMap;

use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::common::traits::Leafable;

use super::merkle_tree::MerkleTree;

pub struct MTWithPrivateLeaves<F: RichField, H: Hasher<F>, V: Leafable<F>> {
    pub merkle_tree: MerkleTree<F, H>,
    pub private_leaves: HashMap<usize, V>,
}
