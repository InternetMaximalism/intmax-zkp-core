use core::fmt::Debug;

use super::{
    node_data::NodeData,
    node_hash::NodeHash,
    proof::{SparseMerkleInclusionProof, SparseMerkleProcessProof},
    root_data::RootData,
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
    R: RootData<I>,
> {
    pub nodes_db: D,
    pub roots_db: R,
    pub _key: core::marker::PhantomData<K>,
    pub _value: core::marker::PhantomData<V>,
    pub _root: core::marker::PhantomData<I>,
    pub _hash: core::marker::PhantomData<H>,
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    From<LayeredLayeredSparseMerkleTree<K, V, I, H, D, R>> for SparseMerkleTree<K, V, I, H, D, R>
{
    fn from(value: LayeredLayeredSparseMerkleTree<K, V, I, H, D, R>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            roots_db: value.roots_db,
            _key: core::marker::PhantomData,
            _value: core::marker::PhantomData,
            _root: core::marker::PhantomData,
            _hash: core::marker::PhantomData,
        }
    }
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    From<SparseMerkleTree<K, V, I, H, D, R>> for LayeredLayeredSparseMerkleTree<K, V, I, H, D, R>
{
    fn from(value: SparseMerkleTree<K, V, I, H, D, R>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            roots_db: value.roots_db,
            _key: core::marker::PhantomData,
            _value: core::marker::PhantomData,
            _root: core::marker::PhantomData,
            _hash: core::marker::PhantomData,
        }
    }
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    LayeredLayeredSparseMerkleTree<K, V, I, H, D, R>
{
    pub fn new(nodes_db: D, roots_db: R) -> Self {
        Self {
            nodes_db,
            roots_db,
            _key: core::marker::PhantomData,
            _value: core::marker::PhantomData,
            _root: core::marker::PhantomData,

            _hash: core::marker::PhantomData,
        }
    }
}

impl<
        K: Sized,
        V: Sized,
        I: Sized + Default,
        H: NodeHash<K, V, I>,
        D: NodeData<K, V, I> + Default,
        R: RootData<I> + Default,
    > Default for LayeredLayeredSparseMerkleTree<K, V, I, H, D, R>
{
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

impl<
        K: KeyLike,
        I: ValueLike + HashLike,
        H: NodeHash<K, I, I>,
        D: NodeData<K, I, I>,
        R: RootData<I>,
    > LayeredLayeredSparseMerkleTree<K, I, I, H, D, R>
{
    pub fn get_root(&self) -> Result<I, R::Error> {
        self.roots_db.get()
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

        self.roots_db
            .set(root_hash)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

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
        let layer1_root = self
            .get_root()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
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

        self.roots_db
            .set(result1.new_root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok((result1, result2, result3))
    }

    pub fn find(
        &self,
        key1: &K,
        key2: &K,
        key3: &K,
    ) -> anyhow::Result<LayeredLayeredSparseMerkleInclusionProof<K, I, I>> {
        let layer1_root = self
            .get_root()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
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
