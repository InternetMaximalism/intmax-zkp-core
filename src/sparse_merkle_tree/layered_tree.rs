use std::fmt::Debug;

use super::{
    node_data::NodeData,
    node_hash::NodeHash,
    proof::{SparseMerkleInclusionProof, SparseMerkleProcessProof},
    tree::{
        calc_inclusion_proof, calc_process_proof, get, HashLike, KeyLike, SparseMerkleTree,
        ValueLike,
    },
};

pub type LayeredSparseMerkleInclusionProof<K, V, I> = (
    SparseMerkleInclusionProof<K, V, I>,
    SparseMerkleInclusionProof<K, V, I>,
);
pub type LayeredSparseMerkleProcessProof<K, V, I> = (
    SparseMerkleProcessProof<K, V, I>,
    SparseMerkleProcessProof<K, V, I>,
);

#[derive(Debug)]
pub struct LayeredSparseMerkleTree<
    K: Sized,
    V: Sized,
    I: Sized,
    H: NodeHash<K, V, I>,
    D: NodeData<K, V, I>,
> {
    pub nodes_db: D,
    pub root: I,
    pub _key: std::marker::PhantomData<K>,
    pub _value: std::marker::PhantomData<V>,
    pub _hash: std::marker::PhantomData<H>,
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>
    From<LayeredSparseMerkleTree<K, V, I, H, D>> for SparseMerkleTree<K, V, I, H, D>
{
    fn from(value: LayeredSparseMerkleTree<K, V, I, H, D>) -> Self {
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
    From<SparseMerkleTree<K, V, I, H, D>> for LayeredSparseMerkleTree<K, V, I, H, D>
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
    LayeredSparseMerkleTree<K, V, I, H, D>
{
    pub fn new(nodes_db: D, root_hash: I) -> Self {
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
    > Default for LayeredSparseMerkleTree<K, V, I, H, D>
{
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

impl<K: KeyLike, I: ValueLike + HashLike, H: NodeHash<K, I, I>, D: NodeData<K, I, I>>
    LayeredSparseMerkleTree<K, I, I, H, D>
{
    pub fn get_root(&self) -> I {
        self.root
    }

    pub fn change_root(&mut self, root_hash: I) -> anyhow::Result<()> {
        if !I::default().eq(&root_hash) {
            let root_node = self.nodes_db.get(&root_hash).map_err(|err| {
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
        value: I,
    ) -> anyhow::Result<LayeredSparseMerkleProcessProof<K, I, I>> {
        let layer1_root = self.get_root();
        let layer2_root = get::<K, I, I, H, D>(&self.nodes_db, &layer1_root, &key1)?;

        let result2 =
            calc_process_proof::<K, I, I, H, D>(&mut self.nodes_db, &layer2_root, key2, value)?;
        let result1 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &layer1_root,
            key1,
            result2.new_root,
        )?;

        self.root = result1.new_root;

        Ok((result1, result2))
    }

    pub fn find(
        &self,
        key1: &K,
        key2: &K,
    ) -> anyhow::Result<LayeredSparseMerkleInclusionProof<K, I, I>> {
        let layer1_root = self.get_root();
        let result1 = calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer1_root, key1)?;
        let layer2_root = if result1.found {
            result1.value
        } else {
            I::default()
        };

        let result2 = calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer2_root, key2)?;

        Ok((result1, result2))
    }
}
