use std::fmt::Debug;

use plonky2::field::goldilocks_field::GoldilocksField;

use crate::sparse_merkle_tree::{
    goldilocks_poseidon::{PoseidonNodeHash, WrappedHashOut},
    node_data::{Node, NodeData},
    node_hash::NodeHash,
    proof::{SparseMerkleInclusionProof, SparseMerkleProcessProof},
    root_data::RootData,
    tree::{calc_inclusion_proof, calc_process_proof, get, SparseMerkleTree},
};

type F = GoldilocksField;
type I = WrappedHashOut<F>;
type K = WrappedHashOut<F>;
type H = PoseidonNodeHash;

/// `(merge_key_layer_proof, contract_address_layer_proof, variable_index_layer_proof)`
pub type UserAssetInclusionProof = (
    SparseMerkleInclusionProof<K, I, I>,
    SparseMerkleInclusionProof<K, I, I>,
    SparseMerkleInclusionProof<K, I, I>,
);

/// `(merge_key_layer_proof, contract_address_layer_proof, variable_index_layer_proof)`
pub type UserAssetProcessProof = (
    SparseMerkleProcessProof<K, I, I>,
    SparseMerkleProcessProof<K, I, I>,
    SparseMerkleProcessProof<K, I, I>,
);

/// merge key layer, contract address layer, variable index layer の 3 層からなる Layered SMT.
/// ただし, `LayeredLayeredSparseMerkleTree` と異なり,
/// contract address layer の root と merge key とを hash したものが merge key layer の leaf hash になる.
#[derive(Clone, Debug)]
pub struct UserAssetTree<D: NodeData<K, I, I>, R: RootData<I>> {
    pub nodes_db: D,
    pub roots_db: R,
}

impl<D: NodeData<K, I, I>, R: RootData<I>> From<UserAssetTree<D, R>>
    for SparseMerkleTree<K, I, I, H, D, R>
{
    fn from(value: UserAssetTree<D, R>) -> Self {
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

impl<D: NodeData<K, I, I>, R: RootData<I>> From<SparseMerkleTree<K, I, I, H, D, R>>
    for UserAssetTree<D, R>
{
    fn from(value: SparseMerkleTree<K, I, I, H, D, R>) -> Self {
        Self {
            nodes_db: value.nodes_db,
            roots_db: value.roots_db,
        }
    }
}

impl<D: NodeData<K, I, I>, R: RootData<I>> UserAssetTree<D, R> {
    pub fn new(nodes_db: D, roots_db: R) -> Self {
        Self { nodes_db, roots_db }
    }
}

impl<D: NodeData<K, I, I>, R: RootData<I>> UserAssetTree<D, R> {
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
        merge_key: K,
        contract_address: K,
        variable_index: K,
        amount: I,
    ) -> anyhow::Result<UserAssetProcessProof> {
        let mut layer0_root = self
            .get_root()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let asset_root = get::<K, I, I, H, D>(&self.nodes_db, &layer0_root, &merge_key)?;
        let (layer1_root, merge_key) = if I::default().eq(&asset_root) {
            (I::default(), merge_key)
        } else {
            // asset_root の子ノードは中間ノードとして記録されている.
            let layer0_children = self
                .nodes_db
                .get(&asset_root)
                .map_err(|err| anyhow::anyhow!("{:?}", err))?;

            match layer0_children {
                Some(Node::Internal(layer1_root, merge_key)) => (layer1_root, merge_key),
                _ => {
                    anyhow::bail!("searching node is not found");
                }
            }
        };

        let mut layer1_root = layer1_root;
        let mut layer2_root =
            get::<K, I, I, H, D>(&self.nodes_db, &layer1_root, &contract_address)?;
        let result2 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &mut layer2_root,
            variable_index,
            amount,
        )?;
        let result1 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &mut layer1_root,
            contract_address,
            layer2_root,
        )?;

        let layer0_children = Node::Internal(layer1_root, merge_key);
        let asset_root = H::calc_node_hash(layer0_children.clone());
        self.nodes_db
            .multi_insert(vec![(asset_root, layer0_children)])
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        let result0 = calc_process_proof::<K, I, I, H, D>(
            &mut self.nodes_db,
            &mut layer0_root,
            merge_key,
            asset_root,
        )?;

        self.roots_db
            .set(layer0_root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok((result0, result1, result2))
    }

    pub fn find(
        &self,
        merge_key: &K,
        contract_address: &K,
        variable_index: &K,
    ) -> anyhow::Result<UserAssetInclusionProof> {
        let layer0_root = self
            .get_root()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let result0 =
            calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer0_root, merge_key)?;

        let layer1_root = if result0.found {
            let asset_root_with_merge = result0.value;
            // asset_root_with_merge の子ノードは中間ノードとして記録されている.
            let layer0_children = self
                .nodes_db
                .get(&asset_root_with_merge)
                .map_err(|err| anyhow::anyhow!("{:?}", err))?;
            match layer0_children {
                Some(Node::Internal(asset_root, found_merge_key)) => {
                    if found_merge_key.ne(merge_key) {
                        anyhow::bail!("fatal error: merge key is invalid");
                    }

                    asset_root
                }
                _ => {
                    anyhow::bail!("searching node is not found");
                }
            }
        } else {
            I::default()
        };

        let result1 =
            calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer1_root, contract_address)?;
        let layer2_root = if result1.found {
            result1.value
        } else {
            I::default()
        };

        let result2 =
            calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer2_root, variable_index)?;

        Ok((result0, result1, result2))
    }

    pub fn get_asset_root(&self, merge_key: &K) -> anyhow::Result<I> {
        let layer0_root = self
            .get_root()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let result0 =
            calc_inclusion_proof::<K, I, I, H, D>(&self.nodes_db, &layer0_root, merge_key)?;

        let asset_root = if result0.found {
            let asset_root_with_merge = result0.value;
            // asset_root_with_merge の子ノードは中間ノードとして記録されている.
            let layer0_children = self
                .nodes_db
                .get(&asset_root_with_merge)
                .map_err(|err| anyhow::anyhow!("{:?}", err))?;
            match layer0_children {
                Some(Node::Internal(asset_root, found_merge_key)) => {
                    if found_merge_key.ne(merge_key) {
                        anyhow::bail!("fatal error: merge key is invalid");
                    }

                    asset_root
                }
                _ => {
                    anyhow::bail!("searching node is not found");
                }
            }
        } else {
            I::default()
        };

        Ok(asset_root)
    }
}
