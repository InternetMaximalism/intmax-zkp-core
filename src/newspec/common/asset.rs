use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

use super::traits::{Leafable, LeafableTarget};

/// Ethereum address is wether 20bytes or 32bytes (256bit)
#[derive(Clone, Debug, Default)]
pub struct ContractAddress([u32; 8]);

#[derive(Clone, Debug, Default)]
pub struct TokenKind<F: RichField> {
    pub contract_address: ContractAddress,
    pub variable_index: F,
}

/// `amount` should be below `MAX_AMOUNT`
#[derive(Clone, Debug, Default)]
pub struct Asset<F: RichField> {
    pub kind: TokenKind<F>,
    pub amount: BigUint,
}

impl<F: RichField> Asset<F> {
    pub(crate) fn to_vec(&self) -> Vec<F> {
        vec![
            self.kind
                .contract_address
                .0
                .into_iter()
                .map(F::from_canonical_u32)
                .collect::<Vec<_>>(),
            vec![self.kind.variable_index],
            self.amount
                .iter_u32_digits()
                .map(F::from_canonical_u32)
                .collect::<Vec<_>>(),
        ]
        .concat()
    }
}

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for Asset<F> {
    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> H::Hash {
        H::hash_no_pad(&self.to_vec())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ContractAddressTarget([U32Target; 8]);

impl ContractAddressTarget {
    pub fn make_constraints<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let targets = builder.add_virtual_u32_targets(8);
        for target in targets.iter() {
            builder.range_check(target.0, 32);
        }

        Self(targets.try_into().unwrap())
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: ContractAddress,
    ) -> Self {
        let targets = value.0.map(|limb| builder.constant_u32(limb));

        Self(targets)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TokenKindTarget {
    pub contract_address: ContractAddressTarget,
    pub variable_index: Target,
}

#[derive(Clone, Debug)]
pub struct AssetTarget {
    pub kind: TokenKindTarget,
    pub amount: BigUintTarget,
}

impl AssetTarget {
    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Asset<F>,
    ) -> Self {
        Self {
            kind: TokenKindTarget {
                contract_address: ContractAddressTarget::constant(
                    builder,
                    value.kind.contract_address,
                ),
                variable_index: builder.constant(value.kind.variable_index),
            },
            amount: builder.constant_biguint(&value.amount),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<Target> {
        [
            self.kind
                .contract_address
                .0
                .iter()
                .map(|v| v.0)
                .collect::<Vec<_>>(),
            vec![self.kind.variable_index],
            self.amount.limbs.iter().map(|v| v.0).collect::<Vec<_>>(),
        ]
        .concat()
    }
}

impl<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize> LeafableTarget<F, H, D>
    for AssetTarget
{
    fn empty_leaf(builder: &mut CircuitBuilder<F, D>) -> Self {
        let empty_leaf = <Asset<F> as Leafable<F, H>>::empty_leaf();

        Self::constant::<F, D>(builder, empty_leaf)
    }

    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_vec())
    }
}
