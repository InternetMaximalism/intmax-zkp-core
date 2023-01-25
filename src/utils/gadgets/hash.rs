use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

pub fn poseidon_two_to_one<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    builder.hash_n_to_hash_no_pad::<H>(vec![
        x.elements[0],
        x.elements[1],
        x.elements[2],
        x.elements[3],
        y.elements[0],
        y.elements[1],
        y.elements[2],
        y.elements[3],
    ])
}
