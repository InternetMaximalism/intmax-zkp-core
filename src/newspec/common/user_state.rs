use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::circuit_builder::CircuitBuilder,
};

use super::traits::{HashableTarget, Leafable};

pub struct UserState<F: RichField> {
    pub asset_root: HashOut<F>,
    pub nullifier_hash_root: HashOut<F>,
    pub public_key: HashOut<F>,
}

impl<F: RichField> Leafable<F> for UserState<F> {
    fn default(&self) -> Self {
        todo!()
    }
    fn hash(&self) -> HashOut<F> {
        todo!()
    }
}

pub struct UserStateTarget {
    pub asset_root: HashOutTarget,
    pub nullifier_hash_root: HashOutTarget,
    pub public_key: HashOutTarget,
}

impl<F: RichField + Extendable<D>, const D: usize> HashableTarget<F, D> for UserStateTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }
}
