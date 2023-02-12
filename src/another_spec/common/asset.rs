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
        let m = self.0.to_vec();

        H::hash_no_pad(&m)
    }
}

impl PartialOrd for Assets {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // different kind of assets cannot be added together
        if self.0.asset_id != other.0.asset_id {
            return None;
        }

        self.0.amount.partial_cmp(&other.0.amount)
    }
}

impl Add for Assets {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(
            self.0.asset_id, rhs.0.asset_id,
            "different kind of assets cannot be added together"
        );

        Self(Asset {
            asset_id: self.0.asset_id,
            amount: self.0.amount.add(rhs.0.amount),
        })
    }
}

impl AddAssign for Assets {
    fn add_assign(&mut self, rhs: Self) {
        let new_assets = self.clone() + rhs;

        let _ = std::mem::replace(self, new_assets);
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
        pw: &mut impl Witness<F>,
        assets: &Assets,
    ) -> anyhow::Result<()> {
        self.0.set_witness(pw, &assets.0)?;

        Ok(())
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        assets: Assets,
        // n_kinds: usize,
    ) -> Self {
        Self(AssetTarget::constant(builder, assets.0))
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self,
        y: &Self,
    ) {
        AssetTarget::connect(builder, &x.0, &y.0);
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self,
        y: &Self,
    ) -> BoolTarget {
        AssetTarget::is_equal(builder, &x.0, &y.0)
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

#[cfg(test)]
mod tests {
    use num::{BigUint, FromPrimitive};

    use crate::newspec::common::asset::{Asset, AssetId};

    use super::Assets;

    #[test]
    fn test_compare_assets() {
        let a = Asset {
            asset_id: AssetId(4),
            amount: BigUint::from_usize(2).unwrap(),
        };
        let b = Asset {
            asset_id: AssetId(4),
            amount: BigUint::from_usize(1).unwrap(),
        };
        let c = Asset {
            asset_id: AssetId(2),
            amount: BigUint::from_usize(1).unwrap(),
        };

        let a = Assets(a);
        let b = Assets(b);
        let c = Assets(c);

        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Greater));
        assert_eq!(a.partial_cmp(&c), None);
    }

    #[test]
    fn test_assets_addition() {
        let a = Asset {
            asset_id: AssetId(4),
            amount: BigUint::from_usize(2).unwrap(),
        };
        let b = Asset {
            asset_id: AssetId(4),
            amount: BigUint::from_usize(1).unwrap(),
        };
        let c = Asset {
            asset_id: AssetId(4),
            amount: BigUint::from_usize(3).unwrap(),
        };

        let a = Assets(a);
        let b = Assets(b);
        let c = Assets(c);

        assert_eq!(a + b, c);
    }

    #[should_panic(expected = "different kind of assets cannot be added together")]
    #[test]
    fn test_difference_assets_addition() {
        let a = Asset {
            asset_id: AssetId(4),
            amount: BigUint::from_usize(2).unwrap(),
        };
        let b = Asset {
            asset_id: AssetId(2),
            amount: BigUint::from_usize(1).unwrap(),
        };

        let a = Assets(a);
        let b = Assets(b);

        let _ = a + b;
    }
}
