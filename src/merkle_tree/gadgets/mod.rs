use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::poseidon::gadgets::poseidon_two_to_one;

use self::utils::conditionally_reverse;

pub mod utils;

#[derive(Clone, Debug)]
pub struct MerkleProofTarget<const N_LEVELS: usize> {
    pub index: Target,
    pub value: HashOutTarget,
    pub siblings: [HashOutTarget; N_LEVELS],
    pub root: HashOutTarget,
}

impl<const N_LEVELS: usize> MerkleProofTarget<N_LEVELS> {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let index = builder.add_virtual_target();
        builder.range_check(index, N_LEVELS);
        let value = builder.add_virtual_hash();
        let siblings: [HashOutTarget; N_LEVELS] =
            builder.add_virtual_hashes(N_LEVELS).try_into().unwrap();
        let root = get_merkle_root_target::<F, H, D>(builder, index, value, &siblings);

        Self {
            index,
            value,
            siblings,
            root,
        }
    }

    pub fn set_witness<F: Field + RichField>(
        &self,
        pw: &mut impl Witness<F>,
        index: F,
        value: HashOut<F>,
        siblings: &[HashOut<F>],
    ) {
        pw.set_target(self.index, index);
        pw.set_hash_target(self.value, value);
        for (ht, value) in self.siblings.iter().zip(siblings.iter()) {
            pw.set_hash_target(*ht, *value);
        }
    }
}

pub fn get_merkle_root_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    index_t: Target,
    value_t: HashOutTarget,
    siblings_t: &[HashOutTarget],
) -> HashOutTarget {
    let mut root_t = value_t;
    let index_le_bits_t = builder.split_le(index_t, siblings_t.len());
    for (sibling_t, lr_bit_t) in siblings_t.iter().zip(index_le_bits_t.into_iter()) {
        let (left, right) = conditionally_reverse(builder, root_t, *sibling_t, lr_bit_t);
        root_t = poseidon_two_to_one::<F, H, D>(builder, left, right);
    }

    root_t
}

pub fn get_merkle_root_target_from_leaves<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    leaves_t: Vec<HashOutTarget>,
) -> HashOutTarget {
    let mut layer = leaves_t;
    assert_ne!(layer.len(), 0);
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().unwrap());
        }

        layer = (0..(layer.len() / 2))
            .map(|i| poseidon_two_to_one::<F, H, D>(builder, layer[2 * i], layer[2 * i + 1]))
            .collect::<Vec<_>>();
    }

    layer[0]
}

#[test]
fn test_verify_merkle_proof_by_plonky2() {
    use std::time::Instant;

    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::tree::get_merkle_proof;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const N_LEVELS: usize = 10;

    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let targets: MerkleProofTarget<10> = MerkleProofTarget::add_virtual_to::<F, H, D>(&mut builder);
    builder.register_public_inputs(&targets.root.elements);
    let data = builder.build::<C>();

    let leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| HashOut {
            elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
        })
        .collect::<Vec<HashOut<_>>>();
    let index = leaves.len() - 1;
    let (siblings, root) = get_merkle_proof(&leaves, index, N_LEVELS);

    let mut pw = PartialWitness::new();
    targets.set_witness(
        &mut pw,
        F::from_canonical_usize(index),
        leaves[index],
        &siblings,
    );

    println!("start proving");
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    assert_eq!(proof.public_inputs[0..4], root.elements[0..4]);

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
