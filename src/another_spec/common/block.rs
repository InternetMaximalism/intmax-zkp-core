use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use super::{
    transaction::{Deposit, TransferBatch},
    utils::Timestamp,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockContentType {
    TransferBatch,
    Deposit,
}

#[derive(Clone, Debug)]
pub enum BlockContent<F: RichField> {
    TransferBatch(TransferBatch<F>),
    Deposit(Deposit),
}

#[derive(Copy, Clone, Debug)]
pub struct BlockHeader<F: RichField> {
    pub previous_block_hash: HashOut<F>,
    pub block_number: u32,
    pub timestamp: Timestamp,
    /// The type of the block content. Can be either TransferBatch or Deposit.
    pub content_type: BlockContentType,
    pub content_hash: HashOut<F>,
}

impl<F: RichField> BlockHeader<F> {
    pub fn get_block_hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}
