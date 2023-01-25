use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::SPONGE_WIDTH,
    },
    iop::target::BoolTarget,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::utils::gadgets::{
    hash::poseidon_two_to_one,
    logic::{conditionally_reverse, is_equal_hash_out, logical_and_not},
};

#[test]
fn test_calc_node_hash() {
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::super::{
        goldilocks_poseidon::PoseidonNodeHash, node_data::Node, node_hash::NodeHash,
    };

    use crate::utils::hash::GoldilocksHashOut;

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

    // dbg!(&data.common);

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

pub fn smt_lev_ins<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    enabled: BoolTarget,
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
    let is_non_zero_last_sibling = logical_and_not(builder, enabled, is_zeros[0]);
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

    // done の値が 0 または 1 であることを検証する
    if cfg!(debug_assertion) {
        builder.assert_bool(*done.last().unwrap());
    }

    // lev_ins[num_levels - 1] = 1 - done[num_levels - 2];
    lev_ins.push(builder.not(*done.last().unwrap()));

    lev_ins.reverse();

    lev_ins
}
