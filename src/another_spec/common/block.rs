use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use super::{
    transaction::{Transfer, TransferBatch},
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
    Deposit(Transfer),
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
    pub fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BlockContentTarget {}

impl BlockContentTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {}
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BlockHeaderTarget {
    pub previous_block_hash: HashOutTarget,
    pub block_number: Target,
    pub timestamp: Target,
    /// The type of the block content. Can be either TransferBatch or Deposit.
    pub is_deposit: BoolTarget,
    pub content_hash: HashOutTarget,
}

impl BlockHeaderTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let previous_block_hash = builder.add_virtual_hash();
        let block_number = builder.add_virtual_target();
        let timestamp = builder.add_virtual_target();
        let is_deposit = builder.add_virtual_bool_target_safe();
        let content_hash = builder.add_virtual_hash();

        Self {
            previous_block_hash,
            block_number,
            timestamp,
            is_deposit,
            content_hash,
        }
    }
}

impl BlockHeaderTarget {
    pub fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        todo!()
    }
}
