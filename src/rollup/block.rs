use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::{
    rollup::{address_list::TransactionSenderWithValidity, gadgets::deposit_block::DepositInfo},
    sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut,
    transaction::block_header::BlockHeader,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockInfo<F: RichField> {
    #[serde(bound(
        serialize = "BlockHeader<F>: Serialize",
        deserialize = "BlockHeader<F>: Deserialize<'de>"
    ))]
    pub header: BlockHeader<F>,
    #[serde(bound(
        serialize = "WrappedHashOut<F>: Serialize",
        deserialize = "WrappedHashOut<F>: Deserialize<'de>"
    ))]
    pub transactions: Vec<WrappedHashOut<F>>,
    #[serde(bound(
        serialize = "WrappedHashOut<F>: Serialize",
        deserialize = "WrappedHashOut<F>: Deserialize<'de>"
    ))]
    pub new_accounts: Vec<WrappedHashOut<F>>,
    #[serde(bound(
        serialize = "DepositInfo<F>: Serialize",
        deserialize = "DepositInfo<F>: Deserialize<'de>"
    ))]
    pub deposit_list: Vec<DepositInfo<F>>,
    #[serde(bound(
        serialize = "TransactionSenderWithValidity<F>: Serialize",
        deserialize = "TransactionSenderWithValidity<F>: Deserialize<'de>"
    ))]
    pub address_list: Vec<TransactionSenderWithValidity<F>>,
    // diff_tree_proof
    // world_state_tree_proof
}

impl<F: RichField> BlockInfo<F> {
    pub fn with_tree_depth(depth: usize) -> Self {
        Self {
            header: BlockHeader::with_tree_depth(depth),
            transactions: Default::default(),
            new_accounts: Default::default(),
            deposit_list: Default::default(),
            address_list: Default::default(),
        }
    }
}
