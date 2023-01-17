use std::{collections::HashMap, fmt::Debug};

use plonky2::{
    hash::{
        hash_types::{HashOut, RichField},
        merkle_proofs::MerkleProof,
    },
    plonk::config::{GenericHashOut, Hasher},
};

use crate::{
    merkle_tree::sparse_merkle_tree::{MerklePath, Node},
    sparse_merkle_tree::goldilocks_poseidon::{le_bytes_to_bits, WrappedHashOut},
    transaction::{
        asset::{Asset, TokenKind, VariableIndex},
        gadgets::purge::encode_asset,
    },
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

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> UserAssetTree<F, H> {
    pub fn new(log_max_n_txs: usize, log_max_n_kinds: usize) -> Self {
        let mut zero_hashes = vec![];

        let zero = vec![F::ZERO; 4];
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

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> UserAssetTree<F, H> {
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
            let parent_path = path[0..path.len() - 1].to_vec();
            self.nodes.insert(
                parent_path.clone(),
                if path[path.len() - 1] {
                    Node::Inner {
                        left: self.get_sibling_hash(&path),
                        right: hash,
                    }
                } else {
                    Node::Inner {
                        left: hash,
                        right: self.get_sibling_hash(&path),
                    }
                },
            );
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
    }

    fn insert(
        &mut self,
        merge_key: &WrappedHashOut<F>,
        token_index: Vec<bool>,
        new_leaf_data: Vec<F>,
    ) {
        let mut merge_key_path = le_bytes_to_bits(&merge_key.to_bytes());
        merge_key_path.resize(self.log_max_n_txs, false);
        let mut path = merge_key_path.clone();
        let mut token_index = token_index;
        path.append(&mut token_index);
        self.nodes.insert(
            path.clone(),
            Node::Leaf {
                data: new_leaf_data,
            },
        );

        self.calc_internal_nodes(&path);
    }

    pub fn insert_assets(
        &mut self,
        merge_key: WrappedHashOut<F>,
        assets: Vec<Asset<F>>,
    ) -> anyhow::Result<()> {
        // let mut merge_key_path = le_bytes_to_bits(&merge_key.to_bytes());
        // merge_key_path.resize(self.log_max_n_txs, false);
        for (i, asset) in assets.iter().enumerate() {
            // let mut path = merge_key_path.clone();
            let new_leaf_data = [merge_key.0.elements.to_vec(), encode_asset(asset)].concat();
            let mut token_index = le_bytes_to_bits(&i.to_le_bytes());
            token_index.resize(self.log_max_n_kinds, false);
            token_index.reverse();
            self.insert(&merge_key.clone(), token_index, new_leaf_data);
        }

        Ok(())
    }

    pub fn remove(
        &mut self,
        merge_key: &WrappedHashOut<F>,
        token_kind: &TokenKind<F>,
    ) -> anyhow::Result<Asset<F>> {
        let path = self
            .nodes
            .iter()
            .find(|v| {
                if let Node::Leaf { data } = v.1 {
                    merge_key.0.elements == data[0..4]
                        && token_kind.contract_address.0.elements == data[4..8]
                        && token_kind.variable_index.to_hash_out().elements == data[8..12]
                } else {
                    false
                }
            })
            .unwrap()
            .0
            .clone();
        let default_leaf_data = vec![F::ZERO; 16];
        let old_leaf_node = self.nodes.insert(
            path.clone(),
            Node::Leaf {
                data: default_leaf_data.clone(),
            },
        );

        self.calc_internal_nodes(&path);

        let old_leaf_data = if let Some(Node::Leaf {
            data: old_leaf_data,
        }) = old_leaf_node
        {
            old_leaf_data
        } else if old_leaf_node.is_none() {
            default_leaf_data
        } else {
            anyhow::bail!("found unexpected inner node");
        };

        Ok(Asset {
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
        let asset_root = self.get_node_hash(&path);

        Ok(asset_root)
    }

    /// Returns `(siblings, path)`
    fn prove(&self, path: &MerklePath) -> anyhow::Result<MerkleProof<F, H>> {
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

        Ok(MerkleProof { siblings })
    }

    pub fn prove_leaf_node(
        &self,
        merge_key: &WrappedHashOut<F>,
        token_kind: &TokenKind<F>,
    ) -> anyhow::Result<(Vec<H::Hash>, MerklePath)> {
        let path = self
            .nodes
            .iter()
            .find(|v| {
                if let Node::Leaf { data } = v.1 {
                    merge_key.0.elements == data[0..4]
                        && token_kind.contract_address.0.elements == data[4..8]
                        && token_kind.variable_index.to_hash_out().elements == data[8..12]
                } else {
                    false
                }
            })
            .unwrap()
            .0;

        let siblings = self.prove(path)?.siblings;

        Ok((siblings, path.to_vec()))
    }

    pub fn prove_asset_root(
        &self,
        merge_key: &H::Hash,
    ) -> anyhow::Result<(Vec<H::Hash>, MerklePath)> {
        let mut path = le_bytes_to_bits(&merge_key.to_bytes());
        path.resize(self.log_max_n_txs, false);

        let siblings = self.prove(&path)?.siblings;

        Ok((siblings, path.to_vec()))
    }
}
