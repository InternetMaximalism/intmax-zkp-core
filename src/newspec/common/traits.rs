use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

/// Can be a leaf of Merkle trees.
pub trait Leafable<F: RichField>: Clone {
    /// Default hash which indicates empty value.
    fn empty_leaf() -> Self;

    /// Hash of its value.
    fn hash<H: Hasher<F>>(&self) -> H::Hash;
}

/// Can be a leaf target of Merkle trees.
pub trait LeafableTarget {
    /// Default constant hash target which indicates empty value.
    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self;

    /// Hash target of its value.
    fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget;
}

impl<F: RichField> Leafable<F> for HashOut<F> {
    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        H::hash_or_noop(&self.elements)
    }
}

impl LeafableTarget for HashOutTarget {
    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = Leafable::<F>::empty_leaf();

        builder.constant_hash(empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_or_noop::<H>(self.elements.to_vec())
    }
}
