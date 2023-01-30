use crate::zkdsa::gadgets::account::AddressTarget;

use super::{
    account::Address,
    asset::TokenKind,
    traits::{HashableTarget, Leafable},
};
use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

/// Transaction which specifies a reciever, a token kind, and an amount.
/// `amount` should be below `MAX_AMOUNT`
pub struct Transaction<F: RichField> {
    pub to: Address<F>,
    pub kind: TokenKind<F>,
    pub amount: BigUint,
    /// Random value which randomize tx_hash
    pub nonce: [F; 4],
}

impl<F: RichField> Leafable<F> for Transaction<F> {
    fn default(&self) -> Self {
        todo!()
    }
    fn hash(&self) -> HashOut<F> {
        todo!()
    }
}

pub struct TransactionTarget {
    pub to: AddressTarget,
    pub kind: Target,
    pub amount: BigUintTarget,
    pub nonce: [Target; 4],
}

impl<F: RichField + Extendable<D>, const D: usize> HashableTarget<F, D> for TransactionTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }
}
