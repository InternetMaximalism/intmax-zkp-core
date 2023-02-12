use std::ops::{Add, AddAssign};

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use crate::newspec::common::asset::{Asset, AssetTarget};

// TODO: Include multiple kinds of assets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assets(pub Asset);

impl Assets {
    // TODO: Pass `salt` as an argument.
    pub fn hash_with_salt<F: RichField, H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

impl PartialOrd for Assets {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Add for Assets {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl AddAssign for Assets {
    fn add_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct AssetsTarget(pub AssetTarget);

impl AssetsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self(AssetTarget::new(builder))
    }

    pub fn set_witness<F: RichField>(
        &self,
        _pw: &mut impl Witness<F>,
        _assets: &Assets,
    ) -> anyhow::Result<()> {
        todo!()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        assets: Assets,
        // n_kinds: usize,
    ) -> Self {
        Self(AssetTarget::constant(builder, assets.0))
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
        _x: &Self,
        _y: &Self,
    ) {
        todo!()
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
        _x: &Self,
        _y: &Self,
    ) -> BoolTarget {
        todo!()
    }

    pub fn hash_with_salt<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        todo!()
    }

    pub fn add<F: RichField + Extendable<D>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
        _x: &Self,
        _y: &Self,
    ) -> Self {
        todo!()
    }

    pub fn is_greater_than<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
        _other: &AssetsTarget,
    ) -> BoolTarget {
        todo!()
    }
}
