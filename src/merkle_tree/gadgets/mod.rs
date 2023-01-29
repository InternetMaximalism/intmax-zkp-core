use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    merkle_tree::tree::KeyLike,
    utils::gadgets::{hash::poseidon_two_to_one, logic::conditionally_reverse},
};

use super::tree::{get_merkle_root, MerkleProcessProof};

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

        Self {
            index,
            value,
            siblings,
            root,
        }
    }

    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        index: &K,
        value: HashOut<F>,
        siblings: &[HashOut<F>],
    ) -> HashOut<F> {
        let mut index = index.to_bits();
        index.resize(self.index.len(), false);
        for (target, value) in self.index.iter().zip(index.iter()) {
            pw.set_bool_target(*target, *value);
        }

        pw.set_hash_target(self.value, value);

        assert_eq!(self.siblings.len(), siblings.len());
        for (sibling_t, sibling) in self.siblings.iter().cloned().zip(siblings.iter().cloned()) {
            pw.set_hash_target(sibling_t, sibling);
        }

        get_merkle_root::<F, H, _, _>(&index, value, siblings)
    }
}

pub fn get_merkle_root_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    index: &[BoolTarget],
    leaf_hash: HashOutTarget,
    siblings: &[HashOutTarget],
) -> HashOutTarget {
    let mut root = leaf_hash;
    assert_eq!(index.len(), siblings.len());
    for (sibling, lr_bit) in siblings.iter().zip(index.iter()) {
        let (left, right) = conditionally_reverse(builder, root, *sibling, *lr_bit);
        root = poseidon_two_to_one::<F, H, D>(builder, left, right);
    }

    root
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

#[derive(Clone, Debug)]
pub struct MerkleProcessProofTarget {
    pub index: Vec<BoolTarget>,
    pub old_value: HashOutTarget,
    pub new_value: HashOutTarget,
    pub siblings: Vec<HashOutTarget>,
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    // pub enabled: BoolTarget
}

impl MerkleProcessProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        n_levels: usize,
    ) -> Self {
        let index = (0..n_levels)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..n_levels)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        let old_root = get_merkle_root_target::<F, H, D>(builder, &index, old_value, &siblings);
        let new_root = get_merkle_root_target::<F, H, D>(builder, &index, new_value, &siblings);

        Self {
            index,
            old_value,
            new_value,
            siblings,
            old_root,
            new_root,
        }
    }

    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        proof: &MerkleProcessProof<F, H, K, HashOut<F>>,
    ) -> (HashOut<F>, HashOut<F>) {
        let mut index = proof.index.to_bits();
        index.resize(self.index.len(), false);
        for (target, value) in self.index.iter().zip(index.iter()) {
            pw.set_bool_target(*target, *value);
        }

        pw.set_hash_target(self.old_value, proof.old_value);
        pw.set_hash_target(self.new_value, proof.new_value);

        assert_eq!(self.siblings.len(), proof.siblings.len());
        for (sibling_t, sibling) in self
            .siblings
            .iter()
            .cloned()
            .zip(proof.siblings.iter().cloned())
        {
            pw.set_hash_target(sibling_t, sibling);
        }

        let old_root = get_merkle_root::<F, H, _, _>(&index, proof.old_value, &proof.siblings);
        let new_root = get_merkle_root::<F, H, _, _>(&index, proof.new_value, &proof.siblings);

        (old_root, new_root)
    }
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

    use super::tree::get_merkle_proof;

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
    let merkle_proof = get_merkle_proof::<F, H>(&leaves, index, N_LEVELS);
    let siblings = merkle_proof.siblings;
    let root = merkle_proof.root();

    let mut pw = PartialWitness::new();
    targets.set_witness::<_, H, _>(&mut pw, &index, leaves[index], &siblings);

    println!("start proving");
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    assert_eq!(proof.public_inputs[0..4], root.elements[0..4]);

    data.verify(proof).unwrap();
}
