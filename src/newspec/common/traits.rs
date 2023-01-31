use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::circuit_builder::CircuitBuilder,
};

/// Can be a leaf of Merkl trees.
pub trait Leafable<F: RichField> {
    /// Default value which indicates empty value.
    fn default(&self) -> Self;

    /// Hash of its value.
    fn hash(&self) -> HashOut<F>;
}

pub(crate) trait HashableTarget<F: RichField + Extendable<D>, const D: usize> {
    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget;
}
