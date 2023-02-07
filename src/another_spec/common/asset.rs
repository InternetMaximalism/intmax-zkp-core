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
