use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::SPONGE_WIDTH,
    },
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

pub fn poseidon_two_to_one<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    builder.hash_n_to_hash_no_pad::<H>([x.elements, y.elements].concat())
}

pub fn poseidon_hash_pad<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[Target],
) -> HashOutTarget {
    let zero = builder.zero();
    let one = builder.one();
    let mut padded_input = input.to_vec();
    padded_input.push(one);
    while (padded_input.len() + 1) % SPONGE_WIDTH != 0 {
        padded_input.push(zero);
    }
    padded_input.push(one);

    builder.hash_n_to_hash_no_pad::<H>(padded_input)
}
