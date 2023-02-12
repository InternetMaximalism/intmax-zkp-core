use std::marker::PhantomData;

use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::common::traits::Leafable;

pub trait NodeData<F: RichField, H: Hasher<F>, V: Leafable<F>> {
    fn new() -> Self;
    fn get_inner_hash(&self, path: &[bool]) -> H::Hash;
    fn get_leaf_data(&self, index: usize) -> V;
    fn insert_inner_hash(&mut self, path: Vec<bool>, value: H::Hash);
    fn insert_leaf_data(&mut self, index: usize, value: H::Hash);
}

/// Sparse Merkle Tree which is compatible to the native plonky2 Merkle Tree.
#[derive(Debug)]
pub struct MerkleTreeTemplate<F: RichField, H: Hasher<F>, V: Leafable<F>, N: NodeData<F, H, V>> {
    pub height: usize,
    pub storage: N,
    pub zero_hashes: Vec<H::Hash>,
    _value: PhantomData<V>,
}

// pub struct NodeDataMemory {
//     node_hashes: HashMap<Vec<bool>, H::Hash>,
//     leaves: HashMap<usize, V>,
// }

// impl NodeData for NodeDataMemory {
//     // ...
// }

// type MerkleTreeMemory<F: RichField, H: Hasher<F>, V: Leafable<F, H>> =
//     MerkleTreeTemplate<F, H, V, NodeDataMemory>;
