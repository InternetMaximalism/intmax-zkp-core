use std::fmt::Debug;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Node<K: Sized, V: Sized, I: Sized> {
    Internal(I, I),
    Leaf(K, V),
}

pub trait NodeData<K: Sized, V: Sized, I: Sized> {
    type Error: 'static + Debug + Sync + Send;

    fn get(&self, key: &I) -> Result<Option<Node<K, V, I>>, Self::Error>;

    #[allow(clippy::type_complexity)]
    fn multi_get(&self, keys: &[I]) -> Result<Vec<Option<Node<K, V, I>>>, Self::Error> {
        keys.iter()
            .map(|key| self.get(key))
            .collect::<Result<Vec<_>, _>>()
    }

    fn multi_insert(&mut self, insert_entries: Vec<(I, Node<K, V, I>)>) -> Result<(), Self::Error>;

    fn multi_delete(&mut self, delete_keys: &[I]) -> Result<(), Self::Error>;
}
