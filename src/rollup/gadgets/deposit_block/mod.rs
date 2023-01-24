use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    sparse_merkle_tree::{
        gadgets::process::{
            process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
            utils::{
                get_process_merkle_proof_role, verify_layered_smt_target_connection,
                ProcessMerkleProofRoleTarget,
            },
        },
        layered_tree::verify_layered_smt_connection,
        proof::ProcessMerkleProofRole,
    },
    utils::hash::WrappedHashOut,
};

#[derive(Clone, Debug)]
pub struct DepositBlockProductionTarget {
    pub deposit_process_proofs: Vec<(
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
    )>, // input

    pub interior_deposit_digest: HashOutTarget, // output

    pub log_n_recipients: usize, // constant
    pub log_n_contracts: usize,  // constant
    pub log_n_variables: usize,  // constant
}

impl DepositBlockProductionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_n_recipients: usize,
        log_n_contracts: usize,
        log_n_variables: usize,
        n_deposits: usize,
    ) -> Self {
        let mut deposit_process_proofs = vec![];
        for _ in 0..n_deposits {
            let targets = (
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_n_recipients,
                ),
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_n_contracts),
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_n_variables),
            );

            deposit_process_proofs.push(targets);
        }

        let interior_deposit_digest =
            calc_deposit_digest::<F, H, D>(builder, &deposit_process_proofs);

        Self {
            deposit_process_proofs,
            interior_deposit_digest,
            log_n_recipients,
            log_n_contracts,
            log_n_variables,
        }
    }

    /// Returns `interior_deposit_digest`
    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        deposit_process_proofs: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
    ) -> HashOut<F> {
        let mut prev_interior_deposit_digest = WrappedHashOut::default();
        assert!(deposit_process_proofs.len() <= self.deposit_process_proofs.len());
        for (proof_t, proof) in self
            .deposit_process_proofs
            .iter()
            .zip(deposit_process_proofs.iter())
        {
            assert_eq!(proof.0.old_root, prev_interior_deposit_digest);
            verify_layered_smt_connection(
                proof.0.fnc,
                proof.0.old_value,
                proof.0.new_value,
                proof.1.old_root,
                proof.1.new_root,
            )
            .unwrap();
            verify_layered_smt_connection(
                proof.1.fnc,
                proof.1.old_value,
                proof.1.new_value,
                proof.2.old_root,
                proof.2.new_root,
            )
            .unwrap();
            assert_eq!(proof.2.fnc, ProcessMerkleProofRole::ProcessInsert);

            proof_t.0.set_witness(pw, &proof.0);
            proof_t.1.set_witness(pw, &proof.1);
            proof_t.2.set_witness(pw, &proof.2);

            prev_interior_deposit_digest = proof.0.new_root;
        }
        let interior_deposit_digest = prev_interior_deposit_digest;

        let default_proof = SmtProcessProof::with_root(Default::default());
        let default_proof0 = SmtProcessProof::with_root(interior_deposit_digest);
        for proof_t in self
            .deposit_process_proofs
            .iter()
            .skip(deposit_process_proofs.len())
        {
            proof_t.0.set_witness(pw, &default_proof0);
            proof_t.1.set_witness(pw, &default_proof);
            proof_t.2.set_witness(pw, &default_proof);
        }

        *interior_deposit_digest
    }
}

/// Returns `(block_tx_root, old_world_state_root, new_world_state_root)`
pub fn calc_deposit_digest<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    deposit_process_proofs: &[(
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
    )],
) -> HashOutTarget {
    let zero = builder.zero();
    let mut interior_deposit_digest = HashOutTarget {
        elements: [zero; 4],
    };
    for proof_t in deposit_process_proofs {
        let ProcessMerkleProofRoleTarget {
            is_insert_or_no_op, ..
        } = get_process_merkle_proof_role(builder, proof_t.2.fnc);
        let constant_true = builder._true();
        builder.connect(is_insert_or_no_op.target, constant_true.target);
        verify_layered_smt_target_connection(
            builder,
            proof_t.0.fnc,
            proof_t.0.old_value,
            proof_t.0.new_value,
            proof_t.1.old_root,
            proof_t.1.new_root,
        );
        verify_layered_smt_target_connection(
            builder,
            proof_t.1.fnc,
            proof_t.1.old_value,
            proof_t.1.new_value,
            proof_t.2.old_root,
            proof_t.2.new_root,
        );

        builder.connect_hashes(proof_t.0.old_root, interior_deposit_digest);
        interior_deposit_digest = proof_t.0.new_root;
    }

    interior_deposit_digest
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        field::types::{Field, Field64},
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        rollup::gadgets::deposit_block::DepositBlockProductionTarget,
        sparse_merkle_tree::goldilocks_poseidon::{
            LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory, RootDataTmp,
        },
        transaction::gadgets::deposit_info::DepositInfo,
        utils::hash::WrappedHashOut,
        zkdsa::account::{private_key_to_account, Address},
    };

    #[test]
    fn test_deposit_block() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        const LOG_N_RECIPIENTS: usize = 3;
        const LOG_N_CONTRACTS: usize = 3;
        const LOG_N_VARIABLES: usize = 3;
        const N_DEPOSITS: usize = 2;

        let sender2_private_key = HashOut {
            elements: [
                F::from_canonical_u64(15657143458229430356),
                F::from_canonical_u64(6012455030006979790),
                F::from_canonical_u64(4280058849535143691),
                F::from_canonical_u64(5153662694263190591),
            ],
        };
        let sender2_account = private_key_to_account(sender2_private_key);
        let sender2_address = sender2_account.address.0;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // builder.debug_gate_row = Some(529); // xors in SparseMerkleProcessProof in DepositBlock

        // deposit block
        let deposit_block_target =
            DepositBlockProductionTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher, D>(
                &mut builder,
                LOG_N_RECIPIENTS,
                LOG_N_CONTRACTS,
                LOG_N_VARIABLES,
                N_DEPOSITS,
            );
        builder.register_public_inputs(&deposit_block_target.interior_deposit_digest.elements);
        let circuit_data = builder.build::<C>();

        let deposit_list = vec![DepositInfo {
            receiver_address: Address(sender2_address),
            contract_address: Address(*WrappedHashOut::from_u128(1)),
            variable_index: 0u8.into(),
            amount: F::from_noncanonical_u64(1),
        }];

        let mut deposit_tree = LayeredLayeredPoseidonSparseMerkleTree::new(
            NodeDataMemory::default(),
            RootDataTmp::default(),
        );
        let deposit_process_proofs = deposit_list
            .iter()
            .map(|leaf| {
                deposit_tree
                    .set(
                        leaf.receiver_address.0.into(),
                        leaf.contract_address.0.into(),
                        leaf.variable_index.to_hash_out().into(),
                        HashOut::from_partial(&[leaf.amount]).into(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let mut pw = PartialWitness::new();
        let interior_deposit_digest =
            deposit_block_target.set_witness::<F, D>(&mut pw, &deposit_process_proofs);

        println!("start proving: block_proof");
        let start = Instant::now();
        let deposit_block_proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        assert_eq!(
            [interior_deposit_digest.elements].concat(),
            deposit_block_proof.public_inputs
        );

        circuit_data.verify(deposit_block_proof).unwrap();

        let mut pw = PartialWitness::new();
        let default_interior_deposit_digest =
            deposit_block_target.set_witness::<F, D>(&mut pw, &[]);

        println!("start proving: block_proof");
        let start = Instant::now();
        let default_deposit_block_proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        assert_eq!(
            [default_interior_deposit_digest.elements].concat(),
            default_deposit_block_proof.public_inputs
        );

        circuit_data.verify(default_deposit_block_proof).unwrap();
    }
}
