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
    sparse_merkle_tree::goldilocks_poseidon::le_bytes_to_bits,
    transaction::asset::{Asset, TokenKind},
    zkdsa::account::Address,
};

#[derive(Debug)]
pub struct TxDiffTree<F: RichField, H: Hasher<F>> {
    pub log_n_recipients: usize, // height of the upper SMT
    pub log_n_kinds: usize,      // height of the lower SMT
    pub nodes: HashMap<MerklePath, Node<F, H>>,
    pub zero: Vec<F>,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> TxDiffTree<F, H> {
    pub fn new(log_n_recipients: usize, log_n_kinds: usize) -> Self {
        let mut zero_hashes = vec![];

        let zero = vec![F::ZERO; 4];
        let node = Node::Leaf::<F, H> { data: zero.clone() };
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 0..(log_n_recipients + log_n_kinds) {
            let node = Node::Inner::<F, H> { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes: HashMap<MerklePath, Node<F, H>> = HashMap::new();

        Self {
            log_n_recipients,
            log_n_kinds,
            nodes,
            zero,
            zero_hashes,
        }
    }
}

impl<F: RichField, H: Hasher<F>> TxDiffTree<F, H> {
    pub fn get_leaf_data(&self, path: &MerklePath) -> Vec<F> {
        assert_eq!(path.len(), self.log_n_recipients + self.log_n_kinds);
        match self.nodes.get(path) {
            Some(Node::Leaf { data }) => data.clone(),
            _ => self.zero.clone(),
        }
    }

    pub fn get_node_hash(&self, path: &MerklePath) -> H::Hash {
        assert!(path.len() <= self.log_n_recipients + self.log_n_kinds);
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

    pub fn insert(&mut self, recipient: Address<F>, asset: Asset<F>) -> anyhow::Result<()> {
        let leaf_data = [
            recipient.elements.to_vec(),
            asset.kind.contract_address.elements.to_vec(),
            asset.kind.variable_index.to_hash_out().elements.to_vec(),
            vec![F::from_canonical_u64(asset.amount)],
        ]
        .concat();
        let mut recipient_path = le_bytes_to_bits(&recipient.to_bytes());
        recipient_path.resize(self.log_n_recipients, false);

        // path が recipient で始まる最も大きいものに 1 を加えた path を求める.
        let mut assets = self
            .nodes
            .iter()
            .filter(|v| v.0.starts_with(&recipient_path))
            .collect::<Vec<_>>();
        assets.sort_by_key(|v| v.0);
        let kind_index = if let Some(last_asset) = assets.last() {
            let mut a = last_asset.0[self.log_n_recipients..].to_vec();
            a.reverse();

            le_bits_to_usize(&a) + 1
        } else {
            0
        };
        let mut kind_path = le_bytes_to_bits(&kind_index.to_le_bytes());
        kind_path.resize(self.log_n_kinds, false);
        kind_path.reverse();
        let mut path = recipient_path;
        path.append(&mut kind_path);

        self.nodes
            .insert(path.clone(), Node::Leaf { data: leaf_data });

        self.calc_internal_nodes(&path);

        Ok(())
    }

    pub fn get_asset_root(&self, recipient: &Address<F>) -> anyhow::Result<H::Hash> {
        let mut path = le_bytes_to_bits(&recipient.to_bytes());
        path.resize(self.log_n_recipients, false);
        let asset_root = self.get_node_hash(&path);

        Ok(asset_root)
    }

    fn prove(&self, path: &MerklePath) -> anyhow::Result<MerkleProof<F, H>> {
        let mut path = path.clone();
        let mut siblings = vec![];
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
        recipient: &Address<F>,
        token_kind: &TokenKind<F>,
    ) -> anyhow::Result<(Vec<H::Hash>, MerklePath)> {
        let path = self
            .nodes
            .iter()
            .find(|v| {
                if let Node::Leaf { data } = v.1 {
                    recipient.0.elements == data[0..4]
                        && token_kind.contract_address.0.elements == data[4..8]
                        && token_kind.variable_index.to_hash_out().elements == data[8..12]
                } else {
                    false
                }
            })
            .unwrap()
            .0;

        debug_assert_eq!(path.len(), self.log_n_recipients + self.log_n_kinds);

        let siblings = self.prove(path)?.siblings;

        Ok((siblings, path.to_vec()))
    }

    pub fn prove_asset_root(
        &self,
        recipient: &Address<F>,
    ) -> anyhow::Result<(Vec<H::Hash>, MerklePath)> {
        let mut path = le_bytes_to_bits(&recipient.to_bytes());
        path.resize(self.log_n_recipients, false);

        let siblings = self.prove(&path)?.siblings;

        Ok((siblings, path.to_vec()))
    }
}

fn le_bits_to_usize(bits: &[bool]) -> usize {
    let mut value: usize = 0;
    let mut powers = 1;
    for bit in bits.iter().take(usize::BITS as usize) {
        if *bit {
            value += powers;
        }

        powers *= 2;
    }

    value
}
