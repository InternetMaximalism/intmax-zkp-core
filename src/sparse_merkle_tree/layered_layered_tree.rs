use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use super::{
    node_data::NodeData,
    node_hash::NodeHash,
    proof::{SparseMerkleInclusionProof, SparseMerkleProcessProof},
    tree::{
        calc_inclusion_proof, calc_process_proof, get, HashLike, KeyLike, SparseMerkleTree,
        ValueLike,
    },
};

pub type LayeredLayeredSparseMerkleInclusionProof<K, V, I> = (
    SparseMerkleInclusionProof<K, V, I>,
    SparseMerkleInclusionProof<K, V, I>,
    SparseMerkleInclusionProof<K, V, I>,
);
pub type LayeredLayeredSparseMerkleProcessProof<K, V, I> = (
    SparseMerkleProcessProof<K, V, I>,
    SparseMerkleProcessProof<K, V, I>,
    SparseMerkleProcessProof<K, V, I>,
);

#[derive(Clone, Debug)]
pub struct LayeredLayeredSparseMerkleTree<
    K: Sized,
    V: Sized,
    I: Sized,
    H: NodeHash<K, V, I>,
    D: NodeData<K, V, I>,
> {
    pub nodes_db: Arc<Mutex<D>>,
    pub root: I,
    pub _key: std::marker::PhantomData<K>,
    pub _value: std::marker::PhantomData<V>,
    pub _hash: std::marker::PhantomData<H>,
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>
    From<LayeredLayeredSparseMerkleTree<K, V, I, H, D>> for SparseMerkleTree<K, V, I, H, D>
{
    fn from(value: LayeredLayeredSparseMerkleTree<K, V, I, H, D>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            root: value.root,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _hash: std::marker::PhantomData,
        }
    }
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>
    From<SparseMerkleTree<K, V, I, H, D>> for LayeredLayeredSparseMerkleTree<K, V, I, H, D>
{
    fn from(value: SparseMerkleTree<K, V, I, H, D>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            root: value.root,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _hash: std::marker::PhantomData,
        }
    }
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>
    LayeredLayeredSparseMerkleTree<K, V, I, H, D>
{
    pub fn new(nodes_db: Arc<Mutex<D>>, root_hash: I) -> Self {
        Self {
            nodes_db,
            root: root_hash,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _hash: std::marker::PhantomData,
        }
    }
}

impl<
        K: Sized,
        V: Sized,
        I: Sized + Default,
        H: NodeHash<K, V, I>,
        D: NodeData<K, V, I> + Default,
    > Default for LayeredLayeredSparseMerkleTree<K, V, I, H, D>
{
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

impl<K: KeyLike, I: ValueLike + HashLike, H: NodeHash<K, I, I>, D: NodeData<K, I, I>>
    LayeredLayeredSparseMerkleTree<K, I, I, H, D>
{
    pub fn get_root(&self) -> I {
        self.root
    }

    pub fn change_root(&mut self, root_hash: I) -> anyhow::Result<()> {
        if !I::default().eq(&root_hash) {
            let root_node = self
                .nodes_db
                .lock()
                .map_err(|err| anyhow::anyhow!("mutex poison error: {}", err))?
                .get(&root_hash)
                .map_err(|err| {
                    anyhow::anyhow!("fail to get node corresponding `root_hash`: {:?}", err)
                })?;

            if root_node.is_none() {
                return Err(anyhow::anyhow!(
                    "the node corresponding `root_hash` does not exist"
                ));
            }
        }

        self.root = root_hash;

        Ok(())
    }

    /// NOTICE: value が 0 のときは entry を削除する.
    pub fn set(
        &mut self,
        key1: K,
        key2: K,
        key3: K,
        value: I,
    ) -> anyhow::Result<LayeredLayeredSparseMerkleProcessProof<K, I, I>> {
        let layer1_root = self.get_root();
        let layer2_root = get::<K, I, I, H, D>(&self.nodes_db, &layer1_root, &key1)?;
        let layer3_root = get::<K, I, I, H, D>(&self.nodes_db, &layer2_root, &key2)?;
        let result3 =
            calc_process_proof::<K, I, I, H, D>(&mut self.nodes_db, &layer3_root, key3, value)?;
        let result2 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &layer2_root,
            key2,
            result3.new_root,
        )?;
        let result1 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &layer1_root,
            key1,
            result2.new_root,
        )?;

        self.root = result1.new_root;

        Ok((result1, result2, result3))
    }

    pub fn find(
        &self,
        key1: &K,
        key2: &K,
        key3: &K,
    ) -> anyhow::Result<LayeredLayeredSparseMerkleInclusionProof<K, I, I>> {
        let layer1_root = self.get_root();
        let result1 = calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer1_root, key1)?;
        let layer2_root = if result1.found {
            result1.value
        } else {
            I::default()
        };

        let result2 = calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer2_root, key2)?;
        let layer3_root = if result2.found {
            result2.value
        } else {
            I::default()
        };

        let result3 = calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer3_root, key3)?;

        Ok((result1, result2, result3))
    }
}
