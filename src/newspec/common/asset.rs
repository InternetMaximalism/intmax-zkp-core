use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

use super::traits::{HashableTarget, Leafable};

pub struct ContractAddress<F: RichField>([F; 8]);

pub struct TokenKind<F: RichField> {
    pub contract_address: ContractAddress<F>,
    pub variable_index: F,
}

/// `amount` should be below `MAX_AMOUNT`
pub struct Asset<F: RichField> {
    pub kind: TokenKind<F>,
    pub amount: BigUint,
}

impl<F: RichField> Leafable<F> for Asset<F> {
    fn default(&self) -> Self {
        todo!()
    }
    fn hash(&self) -> HashOut<F> {
        todo!()
    }
}

pub struct ContractAddressTarget([Target; 8]);

pub struct TokenKindTarget {
    pub contract_address: ContractAddressTarget,
    pub variable_index: Target,
}

pub struct AssetTarget {
    pub kind: TokenKindTarget,
    pub amount: BigUintTarget,
}

impl<F: RichField + Extendable<D>, const D: usize> HashableTarget<F, D> for AssetTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }
}
