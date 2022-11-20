use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

/// if condition { (y, x) } else { (x, y) }
pub(crate) fn conditionally_reverse<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
    condition: BoolTarget,
) -> (HashOutTarget, HashOutTarget) {
    let mut out_left: Vec<Target> = vec![];
    let mut out_right: Vec<Target> = vec![];
    for (x_i, y_i) in x.elements.into_iter().zip(y.elements.into_iter()) {
        let delta_i = builder.sub(y_i, x_i);
        let new_x_i = builder.arithmetic(F::ONE, F::ONE, delta_i, condition.target, x_i);
        let new_y_i = builder.arithmetic(F::NEG_ONE, F::ONE, delta_i, condition.target, y_i);
        out_left.push(new_x_i);
        out_right.push(new_y_i);
    }

    (
        HashOutTarget {
            elements: out_left.try_into().unwrap(),
        },
        HashOutTarget {
            elements: out_right.try_into().unwrap(),
        },
    )
}
