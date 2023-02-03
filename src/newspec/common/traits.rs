use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

/// Can be a leaf of Merkle trees.
pub trait Leafable<F: RichField, H: Hasher<F>>: Clone {
    /// Default hash which indicates empty value.
    fn empty_leaf() -> Self;

    /// Hash of its value.
    fn hash(&self) -> H::Hash;
}

/// Can be a leaf target of Merkle trees.
pub trait LeafableTarget<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize> {
    /// Default constant hash target which indicates empty value.
    fn empty_leaf(builder: &mut CircuitBuilder<F, D>) -> Self;

    /// Hash target of its value.
    fn hash(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget;
}

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> Leafable<F, H> for HashOut<F> {
    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> HashOut<F> {
        *self
    }
}

impl<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize> LeafableTarget<F, H, D>
    for HashOutTarget
{
    fn empty_leaf(builder: &mut CircuitBuilder<F, D>) -> Self {
        let empty_leaf = Leafable::<F, H>::empty_leaf();

        builder.constant_hash(empty_leaf)
    }

    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        *self
    }
}
