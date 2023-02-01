use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use super::traits::{Leafable, LeafableTarget};

#[derive(Clone)]
pub struct UserState<F: RichField> {
    pub asset_root: HashOut<F>,
    pub nullifier_hash_root: HashOut<F>,
    pub public_key: HashOut<F>,
}

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for UserState<F> {
    fn hash(&self) -> H::Hash {
        todo!()
    }

    fn empty_leaf() -> Self {
        todo!()
    }
}

pub struct UserStateTarget {
    pub asset_root: HashOutTarget,
    pub nullifier_hash_root: HashOutTarget,
    pub public_key: HashOutTarget,
}

impl<F: RichField + Extendable<D>, const D: usize> LeafableTarget<F, D> for UserStateTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }

    fn empty_leaf(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }
}
