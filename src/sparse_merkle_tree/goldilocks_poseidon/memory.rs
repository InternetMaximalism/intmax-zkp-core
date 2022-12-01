#![cfg(feature = "std")]

use std::{collections::HashMap, sync::Mutex};

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::Ok;
use plonky2::hash::hash_types::HashOut;

use super::{
    super::{
        node_data::{Node, NodeData},
        root_data::RootData,
    },
    LayeredLayeredPoseidonSparseMerkleTree, LayeredPoseidonSparseMerkleTree,
    PoseidonSparseMerkleTree,
};
use super::{GoldilocksHashOut, Wrapper};

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

pub type PoseidonSparseMerkleTreeMemory = PoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory>;

pub type LayeredPoseidonSparseMerkleTreeMemory =
    LayeredPoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory>;

pub type LayeredLayeredPoseidonSparseMerkleTreeMemory =
    LayeredLayeredPoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory>;
