use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use super::traits::{Leafable, LeafableTarget};

#[derive(Copy, Clone, Debug, Default)]
pub struct UserState<F: RichField> {
    pub asset_root: HashOut<F>,
    pub nullifier_hash_root: HashOut<F>,
    pub public_key: HashOut<F>,
}

impl<F: RichField> UserState<F> {
    pub(crate) fn to_vec(self) -> Vec<F> {
        [
            self.asset_root.elements.to_vec(),
            self.nullifier_hash_root.elements.to_vec(),
            self.public_key.elements.to_vec(),
        ]
        .concat()
    }
}

impl<F: RichField> Leafable<F> for UserState<F> {
    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        H::hash_no_pad(&self.to_vec())
    }

    fn empty_leaf() -> Self {
        Self::default()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UserStateTarget {
    pub asset_root: HashOutTarget,
    pub nullifier_hash_root: HashOutTarget,
    pub public_key: HashOutTarget,
}

impl UserStateTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let asset_root = builder.add_virtual_hash();
        let nullifier_hash_root = builder.add_virtual_hash();
        let public_key = builder.add_virtual_hash();

        Self {
            asset_root,
            nullifier_hash_root,
            public_key,
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, user_state: UserState<F>) {
        pw.set_hash_target(self.asset_root, user_state.asset_root);
        pw.set_hash_target(self.nullifier_hash_root, user_state.nullifier_hash_root);
        pw.set_hash_target(self.public_key, user_state.public_key);
    }

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

    pub(crate) fn to_vec(self) -> Vec<Target> {
        [
            self.asset_root.elements.to_vec(),
            self.nullifier_hash_root.elements.to_vec(),
            self.public_key.elements.to_vec(),
        ]
        .concat()
    }
}

impl LeafableTarget for UserStateTarget {
    fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_or_noop::<H>(self.to_vec())
    }

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = Leafable::<F>::empty_leaf();

        Self::constant::<F, D>(builder, empty_leaf)
    }
}
