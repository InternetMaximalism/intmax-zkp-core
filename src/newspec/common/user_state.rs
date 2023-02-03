use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use super::traits::{Leafable, LeafableTarget};

#[derive(Clone, Debug, Default)]
pub struct UserState<F: RichField> {
    pub asset_root: HashOut<F>,
    pub nullifier_hash_root: HashOut<F>,
    pub public_key: HashOut<F>,
}

impl<F: RichField> UserState<F> {
    pub(crate) fn to_vec(&self) -> Vec<F> {
        [
            self.asset_root.elements.to_vec(),
            self.nullifier_hash_root.elements.to_vec(),
            self.public_key.elements.to_vec(),
        ]
        .concat()
    }
}

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for UserState<F> {
    fn hash(&self) -> H::Hash {
        H::hash_no_pad(&self.to_vec())
    }

    fn empty_leaf() -> Self {
        Self::default()
    }
}

pub struct UserStateTarget {
    pub asset_root: HashOutTarget,
    pub nullifier_hash_root: HashOutTarget,
    pub public_key: HashOutTarget,
}

impl UserStateTarget {
    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: UserState<F>,
    ) -> Self {
        Self {
            asset_root: builder.constant_hash(value.asset_root),
            nullifier_hash_root: builder.constant_hash(value.nullifier_hash_root),
            public_key: builder.constant_hash(value.public_key),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<Target> {
        [
            self.asset_root.elements.to_vec(),
            self.nullifier_hash_root.elements.to_vec(),
            self.public_key.elements.to_vec(),
        ]
        .concat()
    }
}

impl<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize> LeafableTarget<F, H, D>
    for UserStateTarget
{
    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_vec())
    }

    fn empty_leaf(builder: &mut CircuitBuilder<F, D>) -> Self {
        let empty_leaf = <UserState<F> as Leafable<F, H>>::empty_leaf();

        Self::constant::<F, D>(builder, empty_leaf)
    }
}
