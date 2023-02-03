use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

use super::traits::{Leafable, LeafableTarget};

/// Ethereum address is wether 20bytes or 32bytes (256bit)
/// Store 32bit per one field.
#[derive(Clone, Debug, Default)]
pub struct ContractAddress<F: RichField>([F; 8]);

#[derive(Clone, Debug, Default)]
pub struct TokenKind<F: RichField> {
    pub contract_address: ContractAddress<F>,
    pub variable_index: F,
}

/// `amount` should be below `MAX_AMOUNT`
#[derive(Clone, Debug, Default)]
pub struct Asset<F: RichField> {
    pub kind: TokenKind<F>,
    pub amount: BigUint,
}

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for Asset<F> {
    fn empty_leaf() -> Self {
        todo!()
    }
    fn hash(&self) -> H::Hash {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ContractAddressTarget([Target; 8]);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TokenKindTarget {
    pub contract_address: ContractAddressTarget,
    pub variable_index: Target,
}

#[derive(Clone, Debug)]
pub struct AssetTarget {
    pub kind: TokenKindTarget,
    pub amount: BigUintTarget,
}

impl<F: RichField + Extendable<D>, const D: usize> LeafableTarget<F, D> for AssetTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }

    fn empty_leaf(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }
}
