use std::{collections::HashMap, fmt::Debug};

use plonky2::{
    hash::hash_types::RichField,
    plonk::config::{GenericHashOut, Hasher},
};

use crate::{
    merkle_tree::{
        sparse_merkle_tree::{MerklePath, Node},
        tree::MerkleProof,
    },
    sparse_merkle_tree::goldilocks_poseidon::le_bytes_to_bits,
    transaction::{
        asset::{Asset, TokenKind},
        gadgets::purge::encode_asset,
    },
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

impl<F: RichField, H: Hasher<F>> TxDiffTree<F, H> {
    pub fn new(log_n_recipients: usize, log_n_kinds: usize) -> Self {
        let mut zero_hashes = vec![];

        let zero = vec![F::ZERO; 13];
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

    pub fn insert(&mut self, recipient: Address<F>, asset: Asset<F>) -> anyhow::Result<()> {
        let mut recipient_path = le_bytes_to_bits(&recipient.to_bytes());
        recipient_path.resize(self.log_n_recipients, false);
        recipient_path.reverse(); // BE

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
        kind_path.reverse(); // BE

        let mut path = recipient_path;
        path.append(&mut kind_path);

        let leaf_data = [recipient.elements.to_vec(), encode_asset(&asset)].concat();
        debug_assert_eq!(leaf_data.len(), 13);
        self.nodes
            .insert(path.clone(), Node::Leaf { data: leaf_data }); // path: BE

        self.calc_internal_nodes(&path);

        Ok(())
    }

    pub fn get_asset_root(&self, recipient: &Address<F>) -> anyhow::Result<H::Hash> {
        let mut path = le_bytes_to_bits(&recipient.to_bytes());
        path.resize(self.log_n_recipients, false);
        path.reverse();

        let asset_root = self.get_node_hash(&path);

        Ok(asset_root)
    }

    // path: BE
    // siblings: LE
    fn prove(&self, path: &MerklePath) -> anyhow::Result<Vec<H::Hash>> {
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

        Ok(siblings)
    }

    pub fn prove_leaf_node(
        &self,
        recipient: &Address<F>,
        token_kind: &TokenKind<F>,
    ) -> anyhow::Result<MerkleProof<F, H, Vec<bool>>> {
        let mut path = self
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
            .0
            .to_vec();
        dbg!(&path);

        assert_eq!(path.len(), self.log_n_recipients + self.log_n_kinds);

        let siblings = self.prove(&path)?;
        let value = H::hash_or_noop(&self.get_leaf_data(&path));
        let root = self.get_root().unwrap();
        path.reverse(); // BE -> LE
        let proof = MerkleProof::<F, H, Vec<bool>> {
            index: path,
            value,
            siblings,
            root,
        };

        Ok(proof)
    }

    pub fn prove_asset_root(
        &self,
        recipient: &Address<F>,
    ) -> anyhow::Result<MerkleProof<F, H, Vec<bool>>> {
        let mut path = le_bytes_to_bits(&recipient.to_bytes());
        path.resize(self.log_n_recipients, false);
        path.reverse(); // LE -> BE

        let siblings = self.prove(&path)?;
        let value = self.get_asset_root(recipient).unwrap();
        let root = self.get_root().unwrap();
        path.reverse(); // BE -> LE
        let proof = MerkleProof::<F, H, Vec<bool>> {
            index: path,
            value,
            siblings,
            root,
        };

        Ok(proof)
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

#[test]
fn test_prove_tx_diff_tree() {
    use plonky2::{
        field::types::Field,
        hash::hash_types::HashOut,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use crate::{
        merkle_tree::tree::get_merkle_root,
        sparse_merkle_tree::goldilocks_poseidon::GoldilocksHashOut,
        transaction::{
            asset::{Asset, TokenKind, VariableIndex},
            tree::tx_diff::TxDiffTree,
        },
        zkdsa::account::{private_key_to_account, Address},
    };

    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    const LOG_N_RECIPIENTS: usize = 3;
    const LOG_N_CONTRACTS: usize = 3;
    const LOG_N_VARIABLES: usize = 3;

    let asset1 = Asset {
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(305)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 2053,
    };
    let asset2 = Asset {
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(471)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 1111,
    };

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

    let mut deposit_tree =
        TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);

    deposit_tree.insert(user_address, asset1).unwrap();
    deposit_tree.insert(user_address, asset2).unwrap();

    // let proof = deposit_tree.prove_asset_root(&user_address).unwrap();
    let proof = deposit_tree
        .prove_leaf_node(&user_address, &asset2.kind)
        .unwrap();
    let root = get_merkle_root::<_, H, _>(&proof.index, proof.value, &proof.siblings);
    assert_eq!(root, proof.root);
}

#[test]
fn test_tx_diff_tree_by_plonky2() {
    use plonky2::{
        field::types::Field,
        hash::hash_types::HashOut,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use crate::{
        merkle_tree::tree::{get_merkle_proof, get_merkle_root},
        sparse_merkle_tree::goldilocks_poseidon::GoldilocksHashOut,
        transaction::{
            asset::{Asset, TokenKind, VariableIndex},
            tree::tx_diff::TxDiffTree,
        },
        zkdsa::account::{private_key_to_account, Address},
    };

    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    const LOG_N_TXS: usize = 3;
    const LOG_MAX_N_CONTRACTS: usize = 3;
    const LOG_MAX_N_VARIABLES: usize = 3;
    const LOG_N_RECIPIENTS: usize = 3;
    const LOG_N_CONTRACTS: usize = LOG_MAX_N_CONTRACTS;
    const LOG_N_VARIABLES: usize = LOG_MAX_N_VARIABLES;

    let asset1 = Asset {
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(305)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 2053,
    };
    let asset2 = Asset {
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(471)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 1111,
    };

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

    let mut deposit_tree =
        TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);

    deposit_tree.insert(user_address, asset1).unwrap();
    deposit_tree.insert(user_address, asset2).unwrap();

    // let deposit_tree: PoseidonSparseMerkleTree<_, _> = deposit_tree.into();

    let diff_tree_inclusion_proof2 = deposit_tree.prove_asset_root(&user_address).unwrap();
    let interior_deposit_root = deposit_tree.get_root().unwrap();
    assert_eq!(interior_deposit_root, diff_tree_inclusion_proof2.root);

    let deposit_nonce = HashOut::ZERO;
    let deposit_tx_hash = H::two_to_one(interior_deposit_root, deposit_nonce);

    // let diff_tree = TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);
    let diff_tree_inclusion_proof1 = get_merkle_proof::<F, H>(&[deposit_tx_hash], 0, LOG_N_TXS);
    dbg!(&diff_tree_inclusion_proof1);

    let root = get_merkle_root::<F, H, _>(
        &diff_tree_inclusion_proof2.index,
        diff_tree_inclusion_proof2.value,
        &diff_tree_inclusion_proof2.siblings,
    );
    assert_eq!(diff_tree_inclusion_proof2.root, root);

    let root = get_merkle_root::<F, H, _>(
        &diff_tree_inclusion_proof1.index,
        diff_tree_inclusion_proof1.value,
        &diff_tree_inclusion_proof1.siblings,
    );
    assert_eq!(diff_tree_inclusion_proof1.root, root);
}
