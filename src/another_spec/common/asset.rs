use std::ops::{Add, AddAssign};

use plonky2::{hash::hash_types::RichField, plonk::config::Hasher};

use crate::newspec::common::{asset::Asset, traits::Leafable};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assets(pub Vec<Asset>);

impl<F: RichField> Leafable<F> for Assets {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

impl PartialOrd for Assets {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for Assets {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
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

/// Returns `hash_x_with_salt`
pub fn verify_amount_hash<F: RichField, H: Hasher<F>>(
    _x: &Assets,
    /* private */ _salt: [F; 4],
) -> anyhow::Result<H::Hash> {
    // anyhow::ensure!(hash(salt, x) == hash_x_with_salt);
    todo!()
}

/// Returns `(hash_x, hash_y, hash_z)`
pub fn add_amounts<F: RichField, H: Hasher<F>>(
    /* private */ x: Assets,
    /* private */ y: Assets,
    /* private */ z: Assets,
) -> anyhow::Result<(H::Hash, H::Hash, H::Hash)> {
    let hash_x = x.hash::<H>();
    let hash_y = y.hash::<H>();
    let hash_z = z.hash::<H>();
    anyhow::ensure!(x + y == z);

    Ok((hash_x, hash_y, hash_z))
}

/// Returns `(hash_x, hash_y)`
pub fn is_greater_than<F: RichField, H: Hasher<F>>(
    /* private */ x: Assets,
    /* private */ y: Assets,
) -> anyhow::Result<(H::Hash, H::Hash)> {
    let hash_x = x.hash::<H>();
    let hash_y = y.hash::<H>();

    // For multi-asset balances this means that the balance is positive for all assets.
    anyhow::ensure!(x >= y);

    Ok((hash_x, hash_y))
}
