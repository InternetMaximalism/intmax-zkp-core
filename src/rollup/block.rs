use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::{
    rollup::gadgets::deposit_block::DepositInfo,
    sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut,
    transaction::block_header::BlockHeader, zkdsa::account::Address,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
        serialize = "DepositInfo<F>: Serialize",
        deserialize = "DepositInfo<F>: Deserialize<'de>"
    ))]
    pub deposit_list: Vec<DepositInfo<F>>,
    #[serde(bound(
        serialize = "Address<F>: Serialize",
        deserialize = "Address<F>: Deserialize<'de>"
    ))]
    pub address_list: Vec<(Address<F>, bool)>,
    // diff_tree_proof
    // world_state_tree_proof
}
