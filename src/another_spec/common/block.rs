use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use crate::newspec::common::account::Address;

use super::utils::Timestamp;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockContentType {
    TransferBatch,
    Deposit,
}

#[derive(Copy, Clone, Debug)]
pub struct BlockHeader<F: RichField> {
    pub previous_block_hash: HashOut<F>,
    pub block_number: u32,
    pub timestamp: Timestamp,
    /// The type of the block content. Can be either Transfer_batch or Deposit
    pub content_type: BlockContentType,
    pub content_hash: HashOut<F>,
}

pub fn has_positive_balance<F: RichField, H: Hasher<F>>(
    _sender: Address,
    /* private */ _block_header: BlockHeader<F>,
) -> anyhow::Result<H::Hash> {
    todo!()
}
