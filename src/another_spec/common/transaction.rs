use std::collections::HashMap;

use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use crate::{
    another_spec::utils::signature::BlsSignature,
    newspec::{
        common::{account::Address, traits::Leafable},
        utils::merkle_tree::merkle_tree::MerkleTree,
    },
};

use super::asset::Assets;

#[derive(Clone, Debug)]
pub struct Transfer {
    pub recipient: Address,
    pub amount: Assets,
}

impl<F: RichField> Leafable<F> for Transfer {
    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }

    fn empty_leaf() -> Self {
        todo!()
    }
}

#[derive(Debug)]
pub struct TransferTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, Transfer>,
}

#[derive(Debug)]
pub struct TransactionTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, HashOut<F>>,

    /// sender_address -> leaf_index
    pub address_map: HashMap<Address, usize>,
}

#[derive(Clone, Debug)]
pub struct TransferBatch<F: RichField> {
    /// The address of the aggregator for the block
    pub aggregator_address: Address,

    /// The list of senders in the block
    pub sender_list: Vec<Address>,

    /// The root of the transaction tree in the block
    pub transaction_tree_root: HashOut<F>,

    /// An aggregate signature of the transaction tree root by the senders in the block that received
    /// a merkle proof of their transaction in the transaction tree by the sequencer
    pub signature: BlsSignature,
}

impl<F: RichField> Leafable<F> for TransferBatch<F> {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct Deposit {
    pub recipient: Address,
    pub deposited_amount: Assets,
}

impl<F: RichField> Leafable<F> for Deposit {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}
