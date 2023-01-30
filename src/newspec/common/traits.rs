use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::circuit_builder::CircuitBuilder,
};

/// Can be a leaf of Merkl trees.
pub(crate) trait Leafable<F: RichField> {
    fn default(&self) -> Self;
    fn hash(&self) -> HashOut<F>;
}

pub(crate) trait HashableTarget<F: RichField + Extendable<D>, const D: usize> {
    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget;
}
