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

use super::traits::{Leafable, LeafableTarget};

pub const AMOUNT_LIMBS: usize = 8;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId(pub usize);

impl AssetId {
    pub(crate) fn to_vec<F: RichField>(self) -> Vec<F> {
        assert!((self.0 as u64) < F::ORDER);

        vec![F::from_canonical_usize(self.0)]
    }
}

/// `amount` should be below `MAX_AMOUNT`
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Asset {
    pub asset_id: AssetId,
    pub amount: BigUint, // num_limbs: AMOUNT_LIMBS
}

impl Asset {
    pub(crate) fn to_vec<F: RichField>(&self) -> Vec<F> {
        let mut amount = self.amount.to_u32_digits();
        amount.resize(AMOUNT_LIMBS, 0);

        vec![
            self.asset_id.to_vec(),
            amount
                .into_iter()
                .map(F::from_canonical_u32)
                .collect::<Vec<_>>(),
        ]
        .concat()
    }
}

impl<F: RichField> Leafable<F> for Asset {
    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        H::hash_no_pad(&self.to_vec())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AssetIdTarget(pub Target);

impl AssetIdTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self(builder.add_virtual_target())
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        asset_id: AssetId,
    ) -> anyhow::Result<()> {
        anyhow::ensure!((asset_id.0 as u64) < F::ORDER);
        pw.set_target(self.0, F::from_canonical_usize(asset_id.0));

        Ok(())
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        asset_id: AssetId,
    ) -> Self {
        assert!((asset_id.0 as u64) < F::ORDER);

        Self(builder.constant(F::from_canonical_usize(asset_id.0)))
    }

    pub(crate) fn to_vec(self) -> Vec<Target> {
        vec![self.0]
    }
}

#[derive(Clone, Debug)]
pub struct AssetTarget {
    pub asset_id: AssetIdTarget,
    pub amount: BigUintTarget, // num_limbs: CONTRACT_ADDRESS_LIMBS
}

impl AssetTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let asset_id = AssetIdTarget::new(builder);
        let amount = builder.add_virtual_biguint_target(AMOUNT_LIMBS);

        Self { asset_id, amount }
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        asset: &Asset,
    ) -> anyhow::Result<()> {
        self.asset_id.set_witness(pw, asset.asset_id)?;
        pw.set_biguint_target(&self.amount, &asset.amount);

        Ok(())
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        asset: Asset,
    ) -> Self {
        Self {
            asset_id: AssetIdTarget::constant(builder, asset.asset_id),
            amount: builder.constant_biguint(&asset.amount),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<Target> {
        [
            self.asset_id.to_vec(),
            self.amount.limbs.iter().map(|v| v.0).collect::<Vec<_>>(),
        ]
        .concat()
    }
}

impl LeafableTarget for AssetTarget {
    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = Leafable::<F>::empty_leaf();

        Self::constant::<F, D>(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_or_noop::<H>(self.to_vec())
    }
}
