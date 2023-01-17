use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    poseidon::gadgets::poseidon_two_to_one,
    sparse_merkle_tree::{gadgets::common::conditionally_reverse, tree::KeyLike},
};

use super::tree::get_merkle_root;

#[derive(Clone, Debug)]
pub struct MerkleProofTarget {
    pub index: Vec<BoolTarget>,
    pub value: HashOutTarget,
    pub siblings: Vec<HashOutTarget>,
    pub root: HashOutTarget,
    // pub enabled: BoolTarget
}

impl MerkleProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        n_levels: usize,
    ) -> Self {
        let index = (0..n_levels)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();
        let value = builder.add_virtual_hash();
        let siblings = (0..n_levels)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        let root = get_merkle_root_target::<F, H, D>(builder, &index, value, &siblings);
        // let enabled = builder.add_virtual_bool_target_safe();

        Self {
            index,
            value,
            siblings,
            root,
            // enabled
        }
    }

    pub fn set_witness<F: RichField, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        index: K,
        value: HashOut<F>,
        siblings: &[HashOut<F>],
        // enabled: bool,
    ) -> HashOut<F> {
        // pw.set_bool_target(self.enabled, enabled);
        for (target, value) in self.index.iter().zip(index.to_bits().iter()) {
            pw.set_bool_target(*target, *value);
        }

        pw.set_hash_target(self.value, value);

        assert_eq!(self.siblings.len(), siblings.len());
        for (sibling_t, sibling) in self.siblings.iter().cloned().zip(siblings.iter().cloned()) {
            pw.set_hash_target(sibling_t, sibling);
        }

        get_merkle_root::<F, K>(index, value, siblings)
    }
}

pub fn get_merkle_root_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    index_t: &[BoolTarget],
    value_t: HashOutTarget,
    siblings_t: &[HashOutTarget],
) -> HashOutTarget {
    let mut root_t = value_t;
    assert_eq!(index_t.len(), siblings_t.len());
    for (sibling_t, lr_bit_t) in siblings_t.iter().zip(index_t.iter()) {
        let (left, right) = conditionally_reverse(builder, root_t, *sibling_t, *lr_bit_t);
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
        field::types::Field,
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::tree::{get_merkle_proof, MerkleProof};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const N_LEVELS: usize = 10;

    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let targets = MerkleProofTarget::add_virtual_to::<F, H, D>(&mut builder, N_LEVELS);
    builder.register_public_inputs(&targets.root.elements);
    let data = builder.build::<C>();

    let leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| HashOut {
            elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
        })
        .collect::<Vec<_>>();
    let index = leaves.len() - 1;
    let MerkleProof { siblings, root, .. } = get_merkle_proof::<F, H>(&leaves, index, N_LEVELS);

    let mut pw = PartialWitness::new();
    targets.set_witness(&mut pw, index, leaves[index], &siblings);

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
