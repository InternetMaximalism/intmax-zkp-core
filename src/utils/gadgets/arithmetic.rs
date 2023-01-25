//! sparse_merkle_tree を削除した後は不要

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    plonk::circuit_builder::CircuitBuilder,
};

pub fn element_wise_arithmetic<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    const_0: F,
    const_1: F,
    x: HashOutTarget,
    y: HashOutTarget,
    addend: HashOutTarget,
) -> HashOutTarget {
    let output = x
        .elements
        .into_iter()
        .zip(y.elements.into_iter())
        .zip(addend.elements.into_iter())
        .map(|((x_i, y_i), addend_i)| builder.arithmetic(const_0, const_1, x_i, y_i, addend_i))
        .collect::<Vec<_>>();

    HashOutTarget {
        elements: output.try_into().unwrap(),
    }
}

pub fn element_wise_add<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    let one = builder.one();
    let element_wise_one = HashOutTarget { elements: [one; 4] };
    element_wise_arithmetic(builder, F::ONE, F::ONE, x, element_wise_one, y)
}

pub fn element_wise_sub<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    let one = builder.one();
    let element_wise_one = HashOutTarget { elements: [one; 4] };
    element_wise_arithmetic(builder, F::ONE, F::NEG_ONE, x, element_wise_one, y)
}

pub fn element_wise_mul<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    let zero = builder.zero();
    let element_wise_zero = HashOutTarget {
        elements: [zero; 4],
    };
    element_wise_arithmetic(builder, F::ONE, F::ONE, x, y, element_wise_zero)
}
