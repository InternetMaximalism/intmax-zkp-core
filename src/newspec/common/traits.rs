use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

/// Can be a leaf of Merkl trees.
pub trait Leafable<F: RichField, H: Hasher<F>>: Clone {
    /// Default hash which indicates empty value.
    fn empty_leaf() -> Self;

    /// Hash of its value.
    fn hash(&self) -> H::Hash;
}

pub(crate) trait LeafableTarget<F: RichField + Extendable<D>, const D: usize> {
    fn empty_leaf(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget;
    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget;
}
