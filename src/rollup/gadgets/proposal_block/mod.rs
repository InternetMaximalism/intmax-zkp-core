use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
    util::log2_strict,
};

use crate::{
    merkle_tree::{gadgets::get_merkle_root_target_from_leaves, tree::get_merkle_proof_with_zero},
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
    transaction::circuits::{
        MergeAndPurgeTransitionPublicInputs, MergeAndPurgeTransitionPublicInputsTarget,
    },
    utils::{gadgets::logic::logical_or, hash::WrappedHashOut},
};

#[derive(Clone)]
pub struct WorldStateProcessTransitionTarget {
    pub world_state_process_proof: SparseMerkleProcessProofTarget,

    pub user_transaction: MergeAndPurgeTransitionPublicInputsTarget,

    pub enabled: BoolTarget,
}

#[derive(Clone)]
pub struct ProposalBlockProductionTarget {
    pub world_state_process_transitions: Vec<WorldStateProcessTransitionTarget>,

    pub transactions_digest: HashOutTarget, // output

    pub old_world_state_root: HashOutTarget, // input

    pub new_world_state_root: HashOutTarget, // output

    pub log_max_n_users: usize, // constant
}

impl ProposalBlockProductionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_users: usize,
        n_txs: usize,
    ) -> Self {
        // N_TXS は 2 のべき
        assert_eq!(n_txs.next_power_of_two(), n_txs);

        let mut world_state_process_transitions = vec![];
        for _ in 0..n_txs {
            let world_state_process_proof =
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_users); // XXX: row: 529
            let user_transaction =
                MergeAndPurgeTransitionPublicInputsTarget::add_virtual_to(builder);
            let enabled = builder.add_virtual_bool_target_safe();
            world_state_process_transitions.push(WorldStateProcessTransitionTarget {
                world_state_process_proof,
                user_transaction,
                enabled,
            });
        }

        let old_world_state_root = builder.add_virtual_hash();

        let (transactions_digest, new_world_state_root) = verify_valid_proposal_block::<F, H, D>(
            builder,
            &world_state_process_transitions,
            old_world_state_root,
        );

        Self {
            world_state_process_transitions,
            transactions_digest,
            old_world_state_root,
            new_world_state_root,
            log_max_n_users,
        }
    }

    /// Returns `(transactions_digest, new_world_state_root)`.
    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        world_state_process_proofs: &[SmtProcessProof<F>],
        user_transactions: &[MergeAndPurgeTransitionPublicInputs<F>],
        old_world_state_root: WrappedHashOut<F>,
    ) -> (HashOut<F>, HashOut<F>) {
        let n_txs = self.world_state_process_transitions.len();
        pw.set_hash_target(self.old_world_state_root, *old_world_state_root);

        for (w, u) in world_state_process_proofs
            .iter()
            .zip(user_transactions.iter())
        {
            // double spending 防止用のフラグが付いているので u.new_user_asset_root は 0 にならない.
            assert_ne!(
                w.fnc,
                ProcessMerkleProofRole::ProcessDelete,
                "not allowed removing nodes in world state tree"
            );

            verify_layered_smt_connection(
                w.fnc,
                w.old_value,
                w.new_value,
                u.old_user_asset_root, // XXX: middle?
                u.new_user_asset_root,
            )
            .unwrap(); // XXX
        }

        assert!(world_state_process_proofs.len() <= self.world_state_process_transitions.len());
        let mut prev_world_state_root = old_world_state_root;
        for (p_t, p) in self
            .world_state_process_transitions
            .iter()
            .zip(world_state_process_proofs.iter())
        {
            assert_eq!(p.old_root, prev_world_state_root);
            prev_world_state_root = p.new_root;
            p_t.world_state_process_proof.set_witness(pw, p);
        }
        let new_world_state_root = prev_world_state_root;

        let default_proof = SmtProcessProof::with_root(new_world_state_root);
        for p_t in self
            .world_state_process_transitions
            .iter()
            .skip(world_state_process_proofs.len())
        {
            p_t.world_state_process_proof
                .set_witness(pw, &default_proof);
        }

        // assert!(!user_transactions.is_empty());
        assert_eq!(user_transactions.len(), world_state_process_proofs.len());
        for (r_t, r) in self
            .world_state_process_transitions
            .iter()
            .zip(user_transactions.iter())
        {
            r_t.user_transaction.set_witness(pw, r);
            pw.set_bool_target(r_t.enabled, true);
        }

        for r_t in self
            .world_state_process_transitions
            .iter()
            .skip(user_transactions.len())
        {
            r_t.user_transaction.set_witness(pw, &Default::default());
            pw.set_bool_target(r_t.enabled, false);
        }

        let mut transaction_hashes = vec![];
        for u in user_transactions {
            transaction_hashes.push(*u.tx_hash);
        }

        let default_tx_hash = MergeAndPurgeTransitionPublicInputs::<F>::default().tx_hash;

        let log_n_txs = log2_strict(n_txs);
        // let log_n_txs = log2_ceil(n_txs);
        // assert_eq!(2usize.pow(log_n_txs), n_txs);
        let transactions_digest = get_merkle_proof_with_zero::<F, PoseidonHash>(
            &transaction_hashes,
            0,
            log_n_txs,
            *default_tx_hash,
        )
        .root;

        (transactions_digest, *new_world_state_root)
    }
}

/// Returns `(transactions_digest, new_world_state_root)`
pub fn verify_valid_proposal_block<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    world_state_process_transitions: &[WorldStateProcessTransitionTarget],
    old_world_state_root: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let constant_true = builder._true();
    let constant_false = builder._false();

    // world state process proof は正しい遷移になるように並んでいる.
    let mut new_world_state_root = old_world_state_root;
    for t in world_state_process_transitions {
        // let fnc = get_process_merkle_proof_role(builder, proof.fnc);
        // enforce_equal_if_enabled(
        //     builder,
        //     proof.old_root,
        //     new_world_state_root,
        //     fnc.is_not_no_op,
        // );
        builder.connect_hashes(t.world_state_process_proof.old_root, new_world_state_root);

        new_world_state_root = t.world_state_process_proof.new_root;
    }

    // 各 user asset root は world state tree に含まれていることの検証.
    for WorldStateProcessTransitionTarget {
        world_state_process_proof: w,
        user_transaction: u,
        enabled,
    } in world_state_process_transitions
    {
        let ProcessMerkleProofRoleTarget {
            is_no_op,
            is_remove_op,
            ..
        } = get_process_merkle_proof_role(builder, w.fnc);

        // If user transaction is not enabled, corresponding process proof is for noop process.
        let is_no_op_or_enabled = logical_or(builder, is_no_op, *enabled);
        builder.connect(is_no_op_or_enabled.target, constant_true.target);

        // double spending 防止用のフラグが付いているので u.new_user_asset_root は 0 にならない.
        builder.connect(is_remove_op.target, constant_false.target);

        verify_layered_smt_target_connection(
            builder,
            w.fnc,
            w.old_value,
            w.new_value,
            u.old_user_asset_root,
            u.new_user_asset_root,
        );
    }

    // block tx root は block_txs から生まれる Merkle tree の root である.
    let mut transaction_hashes = vec![];
    for t in world_state_process_transitions {
        transaction_hashes.push(t.user_transaction.tx_hash);
    }

    let transactions_digest =
        get_merkle_root_target_from_leaves::<F, H, D>(builder, transaction_hashes);

    (transactions_digest, new_world_state_root)
}

#[cfg(test)]
mod tests {
    use crate::{
        config::RollupConstants,
        rollup::{
            block::make_sample_circuit_inputs,
            gadgets::proposal_block::ProposalBlockProductionTarget,
        },
    };

    #[test]
    fn test_proposal_block() {
        use std::time::Instant;

        use plonky2::{
            iop::witness::PartialWitness,
            plonk::{
                circuit_builder::CircuitBuilder,
                circuit_data::CircuitConfig,
                config::{GenericConfig, PoseidonGoldilocksConfig},
            },
        };

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = <C as GenericConfig<D>>::Hasher;

        let rollup_constants = RollupConstants {
            log_max_n_users: 3,
            log_max_n_txs: 3,
            log_max_n_contracts: 3,
            log_max_n_variables: 3,
            log_n_txs: 2,
            log_n_recipients: 3,
            log_n_contracts: 3,
            log_n_variables: 3,
            n_registrations: 2,
            n_diffs: 2,
            n_merges: 2,
            n_deposits: 2,
            n_blocks: 2,
        };
        let n_txs = 2usize.pow(rollup_constants.log_n_txs as u32);
        let examples = make_sample_circuit_inputs::<C, D>(rollup_constants);

        // proposal block
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proposal_block_target = ProposalBlockProductionTarget::add_virtual_to::<F, H, D>(
            &mut builder,
            rollup_constants.log_max_n_users,
            n_txs,
        );
        builder.register_public_inputs(&proposal_block_target.transactions_digest.elements);
        builder.register_public_inputs(&proposal_block_target.new_world_state_root.elements);
        let circuit_data = builder.build::<C>();

        dbg!(
            &examples[0].world_state_process_proofs,
            &examples[0].approval_block.user_transactions
        );
        let mut pw = PartialWitness::new();
        let (transactions_digest, new_world_state_root) = proposal_block_target
            .set_witness::<F, D>(
                &mut pw,
                &examples[0].world_state_process_proofs,
                &examples[0].approval_block.user_transactions,
                examples[0].old_world_state_root.into(),
                // &examples.world_state_process_proofs,
                // &examples.user_transactions,
                // examples
                //     .world_state_process_proofs
                //     .first()
                //     .unwrap()
                //     .old_root
                //     .into(),
            );

        println!("start proving: block_proof");
        let start = Instant::now();
        let proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        assert_eq!(
            proof.public_inputs,
            [transactions_digest.elements, new_world_state_root.elements].concat()
        );

        circuit_data.verify(proof).unwrap();
    }
}
