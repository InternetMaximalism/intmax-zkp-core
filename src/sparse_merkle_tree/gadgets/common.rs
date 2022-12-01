use alloc::vec;
use alloc::vec::Vec;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::SPONGE_WIDTH,
    },
    iop::target::{BoolTarget, Target},
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

#[test]
fn test_calc_node_hash() {
    use plonky2::{
        iop::witness::{PartialWitness, Witness},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::super::{
        goldilocks_poseidon::{GoldilocksHashOut, PoseidonNodeHash},
        node_data::Node,
        node_hash::NodeHash,
    };

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    // type F = GoldilocksField;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let constant_true = builder.constant_bool(true);
    let constant_false = builder.constant_bool(false);
    let key_t = builder.add_virtual_hash();
    let value_t = builder.add_virtual_hash();
    let out1_t = calc_leaf_hash::<F, H, D>(&mut builder, key_t, value_t);
    let out2_t = calc_internal_hash::<F, H, D>(&mut builder, key_t, value_t, constant_false);
    let out3_t = calc_internal_hash::<F, H, D>(&mut builder, key_t, value_t, constant_true);
    builder.register_public_inputs(&out1_t.elements);
    builder.register_public_inputs(&out2_t.elements);
    builder.register_public_inputs(&out3_t.elements);
    let data = builder.build::<C>();

    dbg!(&data.common);

    let key = GoldilocksHashOut::from_u128(1);
    let value = GoldilocksHashOut::from_u128(2);
    let out1 = PoseidonNodeHash::calc_node_hash(Node::Leaf(key, value));
    let out2 = PoseidonNodeHash::calc_node_hash(Node::Internal(key, value));
    let out3 = PoseidonNodeHash::calc_node_hash(Node::Internal(value, key));

    let mut pw = PartialWitness::new();
    pw.set_hash_target(key_t, *key);
    pw.set_hash_target(value_t, *value);
    pw.set_hash_target(out1_t, *out1);
    pw.set_hash_target(out2_t, *out2);
    pw.set_hash_target(out3_t, *out3);
    let proof = data.prove(pw).unwrap();

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}

pub fn calc_leaf_hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: HashOutTarget,
    value: HashOutTarget,
) -> HashOutTarget {
    let zero = builder.zero();
    let mut perm_inputs = [zero; SPONGE_WIDTH];
    perm_inputs[0..4].copy_from_slice(&key.elements);
    perm_inputs[4..8].copy_from_slice(&value.elements);
    perm_inputs[8] = builder.one();
    perm_inputs[9] = builder.one();
    perm_inputs[11] = builder.one();

    builder.hash_n_to_hash_no_pad::<H>(perm_inputs.to_vec())
}

pub fn calc_internal_hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    child: HashOutTarget,
    sibling: HashOutTarget,
    swap: BoolTarget,
) -> HashOutTarget {
    let (left, right) = conditionally_reverse(builder, child, sibling, swap);

    poseidon_two_to_one::<F, H, D>(builder, left, right)
}

/// if condition { x } else { y }
pub fn conditionally_select<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
    condition: BoolTarget,
) -> HashOutTarget {
    // NOTICE: new_x は使わないので, 最適化される.
    let (_, output) = conditionally_reverse::<F, D>(builder, x, y, condition);

    output
}

/// if condition { (y, x) } else { (x, y) }
pub fn conditionally_reverse<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
    condition: BoolTarget,
) -> (HashOutTarget, HashOutTarget) {
    let mut out_left: Vec<Target> = vec![];
    let mut out_right: Vec<Target> = vec![];
    for (x_i, y_i) in x.elements.into_iter().zip(y.elements.into_iter()) {
        let delta_i = builder.sub(y_i, x_i);
        // let diff_i = builder.mul(delta_i, condition.target);
        // let new_x_i = builder.add(x_i, diff_i);
        // let new_y_i = builder.sub(y_i, diff_i);
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

/// x AND NOT(y)
pub fn logical_and_not<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
) -> BoolTarget {
    // x(1 - y)
    // = x - xy
    let tmp = builder.arithmetic(F::NEG_ONE, F::ONE, x.target, y.target, x.target);

    BoolTarget::new_unsafe(tmp)
}

/// x OR y
pub fn logical_or<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
) -> BoolTarget {
    //   builder.not(builder.and(builder.not(x), builder.not(y)))
    // = 1 - (1 - x)(1 - y)
    // = x + y - xy
    // = x(1 - y) + y
    let x_and_not_y = logical_and_not(builder, x, y);

    BoolTarget::new_unsafe(builder.add(x_and_not_y.target, y.target))
}

/// x implies y
pub fn material_implication<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
) -> BoolTarget {
    let x_and_not_y = logical_and_not(builder, x, y);

    builder.not(x_and_not_y)
}

/// NOT(x OR y)
pub fn logical_nor<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
) -> BoolTarget {
    let not_x = builder.not(x);

    logical_and_not(builder, not_x, y)
}

#[test]
fn test_logical_nor() {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let constant_true = builder.constant_bool(true);
    let constant_false = builder.constant_bool(false);
    let result1 = logical_nor(&mut builder, constant_true, constant_true);
    builder.connect(result1.target, constant_false.target);
    let result2 = logical_nor(&mut builder, constant_true, constant_false);
    builder.connect(result2.target, constant_false.target);
    let result3 = logical_nor(&mut builder, constant_false, constant_true);
    builder.connect(result3.target, constant_false.target);
    let result4 = logical_nor(&mut builder, constant_false, constant_false);
    builder.connect(result4.target, constant_true.target);
    let data = builder.build::<C>();

    dbg!(&data.common);

    let pw = PartialWitness::new();
    let proof = data.prove(pw).unwrap();

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}

/// x XOR y
pub fn logical_xor<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
) -> BoolTarget {
    //   logical_or(builder, builder.and(builder.not(y), x), builder.and(builder.not(x), y))
    // = or(x(1 - y), (1 - x)y)
    // = x(1 - y) + (1 - x)y - x(1 - x)y(1 - y)
    // = x(1 - y) + (1 - x)y
    // = x + y - 2xy
    // = x - (2xy - y)
    let tmp = builder.arithmetic(F::TWO, F::NEG_ONE, x.target, y.target, y.target);

    BoolTarget::new_unsafe(builder.sub(x.target, tmp))
}

/// left == right
pub fn is_equal_hash_out<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: HashOutTarget,
    right: HashOutTarget,
) -> BoolTarget {
    let mut output = builder.constant_bool(true);
    for (l, r) in left.elements.into_iter().zip(right.elements.into_iter()) {
        let l_is_equal_to_r = builder.is_equal(l, r);
        output = builder.and(output, l_is_equal_to_r);
    }

    output
}

pub fn count<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    search_element: HashOutTarget,
    targets: &[HashOutTarget],
) -> Target {
    let one = builder.one();
    let mut counter = builder.zero();
    for target in targets {
        let found = is_equal_hash_out(builder, search_element, *target);
        counter = builder.mul_add(one, found.target, counter)
    }

    counter
}

/// if enabled { assert_eq!(left, right) }
pub fn enforce_equal_if_enabled<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: HashOutTarget,
    right: HashOutTarget,
    enabled: BoolTarget,
) {
    let constant_false = builder.constant_bool(false);
    let output = is_equal_hash_out(builder, left, right);
    let a = logical_and_not(builder, enabled, output);
    builder.connect(a.target, constant_false.target);
}

/// if enabled { assert_ne!(left, right) }
pub fn enforce_not_equal_if_enabled<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: HashOutTarget,
    right: HashOutTarget,
    enabled: BoolTarget,
) {
    let constant_false = builder.constant_bool(false);
    let output = is_equal_hash_out(builder, left, right);
    let a = builder.and(enabled, output);
    builder.connect(a.target, constant_false.target);
}

pub fn smt_lev_ins<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    is_insert_op: BoolTarget,
    siblings: &[HashOutTarget],
) -> Vec<BoolTarget> {
    let constant_false = builder.constant_bool(false);

    let num_levels = siblings.len();

    let zero = builder.zero();

    let mut is_zeros = siblings
        .iter()
        .map(|sibling| {
            is_equal_hash_out(
                builder,
                *sibling,
                HashOutTarget {
                    elements: [zero; 4],
                },
            )
        })
        .collect::<Vec<_>>();

    is_zeros.reverse();

    // The last level must always have a sibling of 0. If not, then it cannot be inserted.
    let is_non_zero_last_sibling = logical_and_not(builder, is_insert_op, is_zeros[0]);
    builder.connect(is_non_zero_last_sibling.target, constant_false.target);

    let mut lev_ins = vec![];
    let mut done = vec![]; // Indicates if the insLevel has already been detected.

    lev_ins.push(builder.not(is_zeros[1])); // lev_ins[0]
    done.push(lev_ins[0]); // done[0]
    for i in 1..(num_levels - 1) {
        let last_done = done.last().unwrap();

        // levIns[i] <== (1-done[i - 1])*(1-isZero[i+1].out);
        let is_non_zero = builder.not(is_zeros[i + 1]);
        lev_ins.push(logical_and_not(builder, is_non_zero, *last_done));

        // done[i] <== levIns[i] + done[i - 1];
        done.push(BoolTarget::new_unsafe(
            builder.add(lev_ins.last().unwrap().target, last_done.target),
        ));
    }

    if cfg!(debug_assertion) {
        builder.assert_bool(*done.last().unwrap());
    }

    // lev_ins[num_levels - 1] = 1 - done[num_levels - 2];
    lev_ins.push(builder.not(*done.last().unwrap()));

    lev_ins.reverse();

    lev_ins
}
