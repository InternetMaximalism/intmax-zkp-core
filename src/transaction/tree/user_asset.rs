use std::{collections::HashMap, fmt::Debug};

use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::{AlgebraicHasher, GenericHashOut, Hasher},
};

use crate::{
    merkle_tree::{
        sparse_merkle_tree::{MerklePath, Node},
        tree::{le_bytes_to_bits, KeyLike, MerkleProof},
    },
    transaction::asset::{ContributedAsset, TokenKind, VariableIndex},
    zkdsa::account::Address,
};

#[derive(Debug)]
pub struct UserAssetTree<F: RichField, H: Hasher<F>> {
    pub log_max_n_txs: usize,   // height of the upper SMT
    pub log_max_n_kinds: usize, // height of the lower SMT
    pub nodes: HashMap<MerklePath, Node<F, H>>,
    pub zero: Vec<F>,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: AlgebraicHasher<F>> UserAssetTree<F, H> {
    pub fn new(log_max_n_txs: usize, log_max_n_kinds: usize) -> Self {
        let mut zero_hashes = vec![];

        let zero = vec![F::ZERO; 13];
        let node = Node::Leaf::<F, H> { data: zero.clone() };
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 1..log_max_n_kinds {
            let node = Node::Inner::<F, H> { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }

        h = HashOut::ZERO;
        zero_hashes.push(h);
        for _ in 0..log_max_n_txs {
            let node = Node::Inner::<F, H> { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes: HashMap<MerklePath, Node<F, H>> = HashMap::new();

        Self {
            log_max_n_txs,
            log_max_n_kinds,
            nodes,
            zero,
            zero_hashes,
        }
    }
}

impl<F: RichField, H: Hasher<F>> UserAssetTree<F, H> {
    pub fn get_leaf_data(&self, path: &MerklePath) -> Vec<F> {
        assert_eq!(path.len(), self.log_max_n_txs + self.log_max_n_kinds);
        match self.nodes.get(path) {
            Some(Node::Leaf { data }) => data.clone(),
            _ => self.zero.clone(),
        }
    }

    pub fn get_node_hash(&self, path: &MerklePath) -> H::Hash {
        assert!(path.len() <= self.log_max_n_txs + self.log_max_n_kinds);
        match self.nodes.get(path) {
            Some(node) => node.hash(),
            None => self.zero_hashes[path.len()],
        }
    }

    pub fn get_root(&self) -> anyhow::Result<H::Hash> {
        let root = self.get_node_hash(&vec![]);

        Ok(root)
    }

    pub fn get_sibling_hash(&self, path: &MerklePath) -> H::Hash {
        assert!(!path.is_empty());
        // TODO maybe more elegant code exists
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];

        self.get_node_hash(&path)
    }

    fn calc_internal_nodes(&mut self, path: &MerklePath) {
        let mut path = path.clone();
        loop {
            let hash = self.get_node_hash(&path);
            // dbg!(&hash);
            let sibling = self.get_sibling_hash(&path);
            let parent_path = path[0..path.len() - 1].to_vec();
            let node = if path[path.len() - 1] {
                Node::Inner {
                    left: sibling,
                    right: hash,
                }
            } else {
                Node::Inner {
                    left: hash,
                    right: sibling,
                }
            };
            // dbg!(&node);
            self.nodes.insert(parent_path.clone(), node);
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
    }

    fn insert(&mut self, merge_key: HashOut<F>, token_index: usize, new_leaf_data: Vec<F>) {
        let mut merge_key_path = le_bytes_to_bits(&merge_key.to_bytes());
        merge_key_path.resize(self.log_max_n_txs, false);
        merge_key_path.reverse();

        let mut kind_path = le_bytes_to_bits(&token_index.to_le_bytes());
        kind_path.resize(self.log_max_n_kinds, false);
        kind_path.reverse();

        let mut path = merge_key_path.clone();
        path.append(&mut kind_path);
        // dbg!(&path);

        debug_assert_eq!(new_leaf_data.len(), 13);
        self.nodes.insert(
            path.clone(),
            Node::Leaf {
                data: new_leaf_data,
            },
        ); // path: BE

        self.calc_internal_nodes(&path);
    }

    pub fn insert_assets(
        &mut self,
        merge_key: HashOut<F>,
        assets: Vec<ContributedAsset<F>>,
    ) -> anyhow::Result<()> {
        for (i, asset) in assets.iter().enumerate() {
            // XXX: `merge_key` does not include in leaf data
            let new_leaf_data = asset.encode();

            self.insert(merge_key, i, new_leaf_data);
        }

        Ok(())
    }

    pub fn remove(
        &mut self,
        merge_key: HashOut<F>,
        user_address: Address<F>,
        token_kind: TokenKind<F>,
    ) -> anyhow::Result<ContributedAsset<F>> {
        let mut merge_key_path = merge_key.to_bits();
        merge_key_path.resize(self.log_max_n_txs, false);
        merge_key_path.reverse();

        let path = self
            .nodes
            .iter()
            .find(|v| {
                if let (node_path, Node::Leaf { data }) = v {
                    node_path.starts_with(&merge_key_path)
                        && user_address.elements == data[0..4]
                        && token_kind.contract_address.to_hash_out().elements == data[4..8]
                        && token_kind.variable_index.to_hash_out().elements == data[8..12]
                } else {
                    false
                }
            })
            .expect("an empty leaf node was found")
            .0
            .clone();
        let old_leaf_node = self.nodes.insert(
            path.clone(),
            Node::Leaf {
                data: self.zero.clone(),
            },
        );

        self.calc_internal_nodes(&path);

        let old_leaf_data = if let Some(Node::Leaf {
            data: old_leaf_data,
        }) = old_leaf_node
        {
            old_leaf_data
        } else if old_leaf_node.is_none() {
            self.zero.clone()
        } else {
            anyhow::bail!("found unexpected inner node");
        };

        Ok(ContributedAsset {
            receiver_address: Address(HashOut::from_partial(&old_leaf_data[0..4])),
            kind: TokenKind {
                contract_address: Address(HashOut::from_partial(&old_leaf_data[4..8])),
                variable_index: VariableIndex::from_hash_out(HashOut::from_partial(
                    &old_leaf_data[8..12],
                )),
            },
            amount: old_leaf_data[12].to_canonical_u64(),
        })
    }

    pub fn get_asset_root(&self, merge_key: &H::Hash) -> anyhow::Result<H::Hash> {
        let mut path = le_bytes_to_bits(&merge_key.to_bytes());
        path.resize(self.log_max_n_txs, false);
        path.reverse();

        let asset_root = self.get_node_hash(&path);

        Ok(asset_root)
    }

    /// Returns `(siblings, path)`
    // path: BE
    // siblings: LE
    fn prove(&self, path: &MerklePath) -> anyhow::Result<Vec<H::Hash>> {
        let mut siblings = vec![];
        let mut path = path.clone();
        loop {
            siblings.push(self.get_sibling_hash(&path));
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }

        Ok(siblings)
    }

    pub fn prove_leaf_node(
        &self,
        merge_key: &H::Hash,
        user_address: &Address<F>,
        token_kind: &TokenKind<F>,
    ) -> anyhow::Result<MerkleProof<F, H, Vec<bool>>> {
        let mut merge_key_path = le_bytes_to_bits(&merge_key.to_bytes());
        merge_key_path.resize(self.log_max_n_txs, false);
        merge_key_path.reverse();

        let mut path = self
            .nodes
            .iter()
            .find(|v| {
                if let (node_path, Node::Leaf { data }) = v {
                    node_path.starts_with(&merge_key_path)
                        && user_address.to_hash_out().elements == data[0..4]
                        && token_kind.contract_address.0.elements == data[4..8]
                        && token_kind.variable_index.to_hash_out().elements == data[8..12]
                } else {
                    false
                }
            })
            .unwrap()
            .0
            .clone();

        assert_eq!(path.len(), self.log_max_n_txs + self.log_max_n_kinds);

        let siblings = self.prove(&path)?;
        let value = H::hash_or_noop(&self.get_leaf_data(&path));
        let root = self.get_root().unwrap();
        path.reverse(); // BE -> LE
        let proof = MerkleProof {
            index: path,
            value,
            siblings,
            root,
        };

        Ok(proof)
    }

    pub fn prove_asset_root(
        &self,
        merge_key: &H::Hash,
    ) -> anyhow::Result<MerkleProof<F, H, Vec<bool>>> {
        let mut path = le_bytes_to_bits(&merge_key.to_bytes());
        path.resize(self.log_max_n_txs, false);
        path.reverse(); // LE -> BE

        let siblings = self.prove(&path)?;
        let value = self.get_asset_root(merge_key).unwrap();
        let root = self.get_root().unwrap();
        path.reverse(); // BE -> LE
        let proof = MerkleProof {
            index: path,
            value,
            siblings,
            root,
        };

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::tree::user_asset::HashOut;
    use crate::transaction::tree::user_asset::UserAssetTree;

    #[test]
    fn test_prove_user_asset_tree() {
        use plonky2::{
            field::types::Field,
            plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
        };

        use crate::{
            merkle_tree::tree::get_merkle_root,
            transaction::asset::{ContributedAsset, TokenKind, VariableIndex},
            utils::hash::GoldilocksHashOut,
            zkdsa::account::{private_key_to_account, Address},
        };

        type C = PoseidonGoldilocksConfig;
        type H = <C as GenericConfig<D>>::InnerHasher;
        type F = <C as GenericConfig<D>>::F;
        const D: usize = 2;

        const LOG_MAX_N_TXS: usize = 3;
        const LOG_MAX_N_CONTRACTS: usize = 3;
        const LOG_MAX_N_VARIABLES: usize = 3;

        let private_key = HashOut {
            elements: [
                F::from_canonical_u64(15657143458229430356),
                F::from_canonical_u64(6012455030006979790),
                F::from_canonical_u64(4280058849535143691),
                F::from_canonical_u64(5153662694263190591),
            ],
        };
        let user_account = private_key_to_account(private_key);
        let user_address = user_account.address;

        let asset1 = ContributedAsset {
            receiver_address: user_address,
            kind: TokenKind {
                contract_address: Address(*GoldilocksHashOut::from_u128(305)),
                variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
            },
            amount: 2053,
        };
        let asset2 = ContributedAsset {
            receiver_address: user_address,
            kind: TokenKind {
                contract_address: Address(*GoldilocksHashOut::from_u128(471)),
                variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
            },
            amount: 1111,
        };

        let mut user_asset_tree =
            UserAssetTree::<F, H>::new(LOG_MAX_N_TXS, LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);

        let merge_key = HashOut {
            elements: [
                F::from_canonical_u64(10129591887907959457),
                F::from_canonical_u64(12952496368791909874),
                F::from_canonical_u64(5623826813413271961),
                F::from_canonical_u64(13962620032426109816),
            ],
        };

        user_asset_tree
            .insert_assets(merge_key, vec![asset1, asset2])
            .unwrap();

        // let proof = deposit_tree.prove_asset_root(&user_address).unwrap();
        let proof = user_asset_tree
            .prove_leaf_node(&merge_key, &user_address, &asset2.kind)
            .unwrap();
        let root = get_merkle_root::<_, H, _>(&proof.index, proof.value, &proof.siblings);
        assert_eq!(root, proof.root);
    }

    #[test]
    fn test_user_asset_tree_by_plonky2() {
        use plonky2::{
            field::types::Field,
            plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
        };

        use crate::{
            merkle_tree::tree::get_merkle_root,
            transaction::{
                asset::{ContributedAsset, TokenKind, VariableIndex},
                tree::user_asset::UserAssetTree,
            },
            utils::hash::GoldilocksHashOut,
            zkdsa::account::{private_key_to_account, Address},
        };

        type C = PoseidonGoldilocksConfig;
        type H = <C as GenericConfig<D>>::InnerHasher;
        type F = <C as GenericConfig<D>>::F;
        const D: usize = 2;

        const LOG_MAX_N_TXS: usize = 3;
        const LOG_MAX_N_CONTRACTS: usize = 3;
        const LOG_MAX_N_VARIABLES: usize = 3;

        let private_key = HashOut {
            elements: [
                F::from_canonical_u64(15657143458229430356),
                F::from_canonical_u64(6012455030006979790),
                F::from_canonical_u64(4280058849535143691),
                F::from_canonical_u64(5153662694263190591),
            ],
        };
        let user_account = private_key_to_account(private_key);
        let user_address = user_account.address;

        let asset1 = ContributedAsset {
            receiver_address: user_address,
            kind: TokenKind {
                contract_address: Address(*GoldilocksHashOut::from_u128(305)),
                variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
            },
            amount: 2053,
        };
        let asset2 = ContributedAsset {
            receiver_address: user_address,
            kind: TokenKind {
                contract_address: Address(*GoldilocksHashOut::from_u128(471)),
                variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
            },
            amount: 1111,
        };

        let mut user_asset_tree =
            UserAssetTree::<F, H>::new(LOG_MAX_N_TXS, LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);

        let deposit_merge_key = HashOut {
            elements: [
                F::from_canonical_u64(10129591887907959457),
                F::from_canonical_u64(12952496368791909874),
                F::from_canonical_u64(5623826813413271961),
                F::from_canonical_u64(13962620032426109816),
            ],
        };

        // user asset tree に deposit を merge する.
        user_asset_tree
            .insert_assets(deposit_merge_key, vec![asset1, asset2])
            .unwrap();

        let merge_inclusion_proof = user_asset_tree
            .prove_asset_root(&deposit_merge_key)
            .unwrap();

        let root = get_merkle_root::<F, H, _>(
            &merge_inclusion_proof.index,
            merge_inclusion_proof.value,
            &merge_inclusion_proof.siblings,
        );
        assert_eq!(merge_inclusion_proof.root, root);
    }
}
