use std::fmt::Debug;

use super::{
    node_data::NodeData,
    node_hash::NodeHash,
    proof::{ProcessMerkleProofRole, SparseMerkleInclusionProof, SparseMerkleProcessProof},
    root_data::RootData,
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
    R: RootData<I>,
> {
    pub nodes_db: D,
    pub roots_db: R,
    pub _key: std::marker::PhantomData<K>,
    pub _value: std::marker::PhantomData<V>,
    pub _root: std::marker::PhantomData<I>,
    pub _hash: std::marker::PhantomData<H>,
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    From<LayeredSparseMerkleTree<K, V, I, H, D, R>> for SparseMerkleTree<K, V, I, H, D, R>
{
    fn from(value: LayeredSparseMerkleTree<K, V, I, H, D, R>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            roots_db: value.roots_db,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _root: std::marker::PhantomData,
            _hash: std::marker::PhantomData,
        }
    }
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    From<SparseMerkleTree<K, V, I, H, D, R>> for LayeredSparseMerkleTree<K, V, I, H, D, R>
{
    fn from(value: SparseMerkleTree<K, V, I, H, D, R>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            roots_db: value.roots_db,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _root: std::marker::PhantomData,
            _hash: std::marker::PhantomData,
        }
    }
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    LayeredSparseMerkleTree<K, V, I, H, D, R>
{
    pub fn new(nodes_db: D, roots_db: R) -> Self {
        Self {
            nodes_db,
            roots_db,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _root: std::marker::PhantomData,
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
        R: RootData<I> + Default,
    > Default for LayeredSparseMerkleTree<K, V, I, H, D, R>
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
    > LayeredSparseMerkleTree<K, I, I, H, D, R>
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
        value: I,
    ) -> anyhow::Result<LayeredSparseMerkleProcessProof<K, I, I>> {
        let mut layer1_root = self
            .get_root()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let mut layer2_root = get::<K, I, I, H, D>(&self.nodes_db, &layer1_root, &key1)?;
        let result2 =
            calc_process_proof::<K, I, I, H, D>(&mut self.nodes_db, &mut layer2_root, key2, value)?;
        let result1 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &mut layer1_root,
            key1,
            layer2_root,
        )?;

        self.roots_db
            .set(layer1_root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok((result1, result2))
    }

    pub fn find(
        &self,
        key1: &K,
        key2: &K,
    ) -> anyhow::Result<LayeredSparseMerkleInclusionProof<K, I, I>> {
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

        Ok((result1, result2))
    }
}

pub fn verify_layered_smt_connection<I: Default + PartialEq>(
    upper_smt_fnc: ProcessMerkleProofRole,
    old_upper_smt_value: I,
    new_upper_smt_value: I,
    old_lower_smt_root: I,
    new_lower_smt_root: I,
) -> anyhow::Result<()> {
    match upper_smt_fnc {
        ProcessMerkleProofRole::ProcessUpdate => {
            if old_lower_smt_root != old_upper_smt_value {
                anyhow::bail!("`old_lower_smt_root` must be the same with `old_upper_smt_value` in the case of updating a node");
            }

            if new_lower_smt_root != new_upper_smt_value {
                anyhow::bail!("`new_lower_smt_root` must be the same with `new_upper_smt_value` in the case of updating a node");
            }
        }
        ProcessMerkleProofRole::ProcessInsert => {
            if old_lower_smt_root != I::default() {
                anyhow::bail!(
                    "`old_lower_smt_root` must be the default value in the case of inserting a node"
                );
            }

            if new_lower_smt_root != new_upper_smt_value {
                anyhow::bail!("`new_lower_smt_root` must be the same with `new_upper_smt_value` in the case of inserting a node");
            }
        }
        ProcessMerkleProofRole::ProcessDelete => {
            if old_lower_smt_root != old_upper_smt_value {
                anyhow::bail!("`old_lower_smt_root` must be the same with `old_upper_smt_value` in the case of removing a node");
            }

            if new_lower_smt_root != I::default() {
                anyhow::bail!(
                    "`new_lower_smt_root` must be the default value in the case of removing a node"
                );
            }
        }
        ProcessMerkleProofRole::ProcessNoOp => {
            if old_lower_smt_root != I::default() {
                anyhow::bail!(
                    "`old_lower_smt_root` must be the default value in the case of no-operation"
                );
            }

            if new_lower_smt_root != I::default() {
                anyhow::bail!(
                    "`new_lower_smt_root` must be the default value in the case of no-operation"
                );
            }
        }
    }

    Ok(())
}
