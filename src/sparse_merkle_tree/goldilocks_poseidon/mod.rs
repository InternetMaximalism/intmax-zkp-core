use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Ok;
use num::Integer;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{GenericHashOut, Hasher},
};

use super::{
    goldilocks_poseidon,
    layered_layered_tree::LayeredLayeredSparseMerkleTree,
    layered_tree::LayeredSparseMerkleTree,
    node_data::{Node, NodeData},
    node_hash::NodeHash,
    root_data::RootData,
    tree::{HashLike, KeyLike, SparseMerkleTree, ValueLike},
};

mod hash;
pub use self::hash::{GoldilocksHashOut, WrappedHashOut, Wrapper};

pub fn le_bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| {
            let mut byte = *byte;
            let mut res = vec![];
            for _ in 0..8 {
                res.push(byte.is_odd());
                byte >>= 1;
            }
            res
        })
        .collect::<Vec<_>>()
}

impl KeyLike for GoldilocksHashOut {
    fn to_bits(&self) -> Vec<bool> {
        let bytes = self.0.to_bytes();

        le_bytes_to_bits(&bytes)
    }
}

impl ValueLike for GoldilocksHashOut {}

impl HashLike for GoldilocksHashOut {}

type K = GoldilocksHashOut;
type V = GoldilocksHashOut;
type I = GoldilocksHashOut;

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug, Default)]
pub struct NodeDataMemory {
    pub nodes: Arc<Mutex<HashMap<K, Node<K, V, I>>>>,
}

impl NodeData<K, V, I> for NodeDataMemory {
    type Error = anyhow::Error;

    fn get(&self, key: &I) -> Result<Option<Node<K, V, I>>, Self::Error> {
        if let Some(some_data) = self.nodes.lock().expect("mutex poison error").get(key) {
            Ok(Some(some_data.clone()))
        } else {
            Ok(None)
        }
    }

    fn multi_insert(&mut self, insert_entries: Vec<(I, Node<K, V, I>)>) -> Result<(), Self::Error> {
        for (key, value) in insert_entries {
            self.nodes
                .lock()
                .expect("mutex poison error")
                .insert(key, value);
        }

        Ok(())
    }

    fn multi_delete(&mut self, _delete_keys: &[I]) -> Result<(), Self::Error> {
        // あとで過去の root を参照したい時に役立つので消さない.
        // for key in _delete_keys {
        //     self.nodes.remove(key);
        // }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RootDataMemory {
    pub roots: Arc<Mutex<Vec<I>>>,
}

impl Default for RootDataMemory {
    fn default() -> Self {
        let data = vec![Wrapper(HashOut::ZERO)];
        Self {
            roots: Arc::new(Mutex::new(data)),
        }
    }
}

impl From<I> for RootDataMemory {
    fn from(value: I) -> Self {
        let data = vec![value];
        Self {
            roots: Arc::new(Mutex::new(data)),
        }
    }
}

impl RootData<I> for RootDataMemory {
    type Error = anyhow::Error;

    fn get(&self) -> Result<I, Self::Error> {
        let result = *self.roots.lock().unwrap().last().unwrap();

        Ok(result)
    }

    fn set(&mut self, root: I) -> Result<(), Self::Error> {
        self.roots.lock().unwrap().push(root);

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct RootDataTmp(pub I);

impl From<I> for RootDataTmp {
    fn from(value: I) -> Self {
        Self(value)
    }
}

impl RootData<I> for RootDataTmp {
    type Error = anyhow::Error;

    fn get(&self) -> Result<I, Self::Error> {
        Ok(self.0)
    }

    fn set(&mut self, root: I) -> Result<(), Self::Error> {
        let _ = std::mem::replace(self, Self(root));

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoseidonNodeHash {}

impl NodeHash<K, V, I> for PoseidonNodeHash {
    fn calc_node_hash(node: Node<K, V, I>) -> I {
        match node {
            Node::Internal(left, right) => {
                goldilocks_poseidon::Wrapper(PoseidonHash::two_to_one(*left, *right))
            }
            Node::Leaf(key, value) => {
                let left = key.elements;
                let right = value.elements;
                goldilocks_poseidon::Wrapper(PoseidonHash::hash_pad(&[
                    left[0],
                    left[1],
                    left[2],
                    left[3],
                    right[0],
                    right[1],
                    right[2],
                    right[3],
                    GoldilocksField(1),
                ]))
            }
        }
    }
}

pub type PoseidonSparseMerkleTree<D, R> = SparseMerkleTree<K, V, I, PoseidonNodeHash, D, R>;

pub type LayeredPoseidonSparseMerkleTree<D, R> =
    LayeredSparseMerkleTree<K, V, I, PoseidonNodeHash, D, R>;

pub type LayeredLayeredPoseidonSparseMerkleTree<D, R> =
    LayeredLayeredSparseMerkleTree<K, V, I, PoseidonNodeHash, D, R>;

pub type PoseidonSparseMerkleTreeMemory = PoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory>;

pub type LayeredPoseidonSparseMerkleTreeMemory =
    LayeredPoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory>;

pub type LayeredLayeredPoseidonSparseMerkleTreeMemory =
    LayeredLayeredPoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory>;
