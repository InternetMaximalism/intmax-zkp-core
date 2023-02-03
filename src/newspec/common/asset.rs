use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint};
use plonky2_u32::{
    gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
    witness::WitnessU32,
};

use super::traits::{Leafable, LeafableTarget};

/// Ethereum address is wether 20bytes or 32bytes (256bit)
#[derive(Copy, Clone, Debug, Default)]
pub struct ContractAddress([u32; 8]);

#[derive(Copy, Clone, Debug, Default)]
pub struct TokenKind<F: RichField> {
    pub contract_address: ContractAddress,
    pub variable_index: F,
}

impl<F: RichField> TokenKind<F> {
    pub(crate) fn to_vec(self) -> Vec<F> {
        vec![
            self.contract_address
                .0
                .into_iter()
                .map(F::from_canonical_u32)
                .collect::<Vec<_>>(),
            vec![self.variable_index],
        ]
        .concat()
    }
}

/// `amount` should be below `MAX_AMOUNT`
#[derive(Clone, Debug, Default)]
pub struct Asset<F: RichField> {
    pub kind: TokenKind<F>,
    pub amount: BigUint, // num_limbs: 8
}

impl<F: RichField> Asset<F> {
    pub(crate) fn to_vec(&self) -> Vec<F> {
        let mut amount = self.amount.to_u32_digits();
        amount.resize(8, 0);

        vec![
            self.kind.to_vec(),
            amount
                .into_iter()
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

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        contract_address: ContractAddress,
    ) {
        for (target, value) in self.0.iter().zip(contract_address.0.iter()) {
            pw.set_u32_target(*target, *value);
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: ContractAddress,
    ) -> Self {
        let targets = value.0.map(|limb| builder.constant_u32(limb));

        Self(targets)
    }

    pub(crate) fn to_vec(self) -> Vec<Target> {
        self.0.iter().map(|v| v.0).collect::<Vec<_>>()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TokenKindTarget {
    pub contract_address: ContractAddressTarget,
    pub variable_index: Target,
}

impl TokenKindTarget {
    pub fn make_constraints<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let contract_address = ContractAddressTarget::make_constraints(builder);
        let variable_index = builder.add_virtual_target();

        Self {
            contract_address,
            variable_index,
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, kind: TokenKind<F>) {
        self.contract_address.set_witness(pw, kind.contract_address);
        pw.set_target(self.variable_index, kind.variable_index);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: TokenKind<F>,
    ) -> Self {
        Self {
            contract_address: ContractAddressTarget::constant(builder, value.contract_address),
            variable_index: builder.constant(value.variable_index),
        }
    }

    pub(crate) fn to_vec(self) -> Vec<Target> {
        [self.contract_address.to_vec(), vec![self.variable_index]].concat()
    }
}

#[derive(Clone, Debug)]
pub struct AssetTarget {
    pub kind: TokenKindTarget,
    pub amount: BigUintTarget, // num_limbs: 8
}

impl AssetTarget {
    pub fn make_constraints<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let kind = TokenKindTarget::make_constraints(builder);
        let amount = builder.add_virtual_biguint_target(8);

        Self { kind, amount }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, asset: &Asset<F>) {
        self.kind.set_witness(pw, asset.kind);
        pw.set_biguint_target(&self.amount, &asset.amount);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Asset<F>,
    ) -> Self {
        Self {
            kind: TokenKindTarget::constant(builder, value.kind),
            amount: builder.constant_biguint(&value.amount),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<Target> {
        [
            self.kind.to_vec(),
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
