use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

/// Can be a leaf of Merkl trees.
pub trait Leafable<F: RichField, H: Hasher<F>>: Clone {
    /// Default hash which indicates empty value.
    fn default_hash() -> H::Hash;

    /// Hash of its value.
    fn hash(&self) -> H::Hash;
}

pub(crate) trait HashableTarget<F: RichField + Extendable<D>, const D: usize> {
    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget;
}
