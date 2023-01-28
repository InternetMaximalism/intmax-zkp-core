use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    sparse_merkle_tree::gadgets::process::process_smt::{
        SmtProcessProof, SparseMerkleProcessProofTarget,
    },
    transaction::circuits::{
        MergeAndPurgeTransitionPublicInputs, MergeAndPurgeTransitionPublicInputsTarget,
    },
    utils::{
        gadgets::logic::{conditionally_select, enforce_equal_if_enabled},
        hash::WrappedHashOut,
    },
    zkdsa::circuits::{SimpleSignaturePublicInputs, SimpleSignaturePublicInputsTarget},
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedMessage<F: RichField> {
    message: HashOut<F>,
    public_key: HashOut<F>,
    signature: HashOut<F>,
}

#[derive(Clone)]
pub struct WorldStateRevertTransitionTarget {
    pub world_state_revert_proof: SparseMerkleProcessProofTarget,

    pub user_transaction: MergeAndPurgeTransitionPublicInputsTarget,

    pub received_signature: (SimpleSignaturePublicInputsTarget, BoolTarget),

    pub latest_account_process_proof: SparseMerkleProcessProofTarget,

    pub enabled: BoolTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalBlockProduction<F: RichField> {
    pub current_block_number: u32,
    pub world_state_revert_proofs: Vec<SmtProcessProof<F>>,
    pub user_transactions: Vec<MergeAndPurgeTransitionPublicInputs<F>>,
    pub received_signatures: Vec<Option<SimpleSignaturePublicInputs<F>>>,
    pub latest_account_tree_process_proofs: Vec<SmtProcessProof<F>>,
    pub old_world_state_root: WrappedHashOut<F>,
    pub old_latest_account_root: WrappedHashOut<F>,
}

impl<F: RichField> ApprovalBlockProduction<F> {
    /// Returns `(new_world_state_root, new_latest_account_root)`
    pub fn calculate(&self) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
        let mut prev_world_state_root = self.old_world_state_root;
        let mut prev_latest_account_root = self.old_latest_account_root;
        for (world_state_revert_proof, latest_account_process_proof) in self
            .world_state_revert_proofs
            .iter()
            .zip(self.latest_account_tree_process_proofs.iter())
        {
            assert_eq!(world_state_revert_proof.old_root, prev_world_state_root);
            assert_eq!(
                latest_account_process_proof.old_root,
                prev_latest_account_root
            );

            prev_world_state_root = world_state_revert_proof.new_root;
            prev_latest_account_root = latest_account_process_proof.new_root;
        }
        let new_world_state_root = prev_world_state_root;
        let new_latest_account_root = prev_latest_account_root;

        for (((w, u), r), a) in self
            .world_state_revert_proofs
            .iter()
            .zip(self.user_transactions.iter())
            .zip(self.received_signatures.iter())
            .zip(self.latest_account_tree_process_proofs.iter())
        {
            // proposed block では, user asset root は `u.new_user_asset_root` と同じであった.
            assert_eq!(w.old_value, u.new_user_asset_root);

            // merge までは signature がなくても実行されるが, purge は signature がない時には実行されない.
            let expected_new_last_block_number = if let Some(signature) = r {
                // signature が特定のメッセージに署名している時のみ有効である.
                assert_eq!(
                    signature.message,
                    self.old_world_state_root.0.elements.to_vec()
                );
                // signature が提出された時, user asset root は変わらない.
                assert_eq!(w.new_value, u.new_user_asset_root);

                WrappedHashOut::from_u32(self.current_block_number)
            } else {
                // signature がない時は, user asset root が merge 直後の状態 `u.middle_user_asset_root` に更新される
                assert_eq!(w.new_value, u.middle_user_asset_root);

                a.old_value
            };

            assert_eq!(a.new_value, expected_new_last_block_number);
        }

        (new_world_state_root, new_latest_account_root)
    }
}

#[derive(Clone)]
pub struct ApprovalBlockProductionTarget {
    pub current_block_number: Target,

    pub world_state_revert_transitions: Vec<WorldStateRevertTransitionTarget>,

    pub old_world_state_root: HashOutTarget,

    pub new_world_state_root: HashOutTarget,

    pub old_latest_account_root: HashOutTarget,

    pub new_latest_account_root: HashOutTarget,

    pub log_max_n_users: usize, // constant
}

impl ApprovalBlockProductionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_users: usize,
        n_txs: usize,
    ) -> Self {
        let current_block_number = builder.add_virtual_target();

        let mut world_state_revert_transitions = vec![];
        for _ in 0..n_txs {
            let world_state_revert_proof =
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_users);
            let user_transaction =
                MergeAndPurgeTransitionPublicInputsTarget::add_virtual_to(builder);
            let signature = SimpleSignaturePublicInputsTarget::add_virtual_to(builder);
            let validity = builder.add_virtual_bool_target_safe();
            let latest_account_process_proof =
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_users);
            let enabled = builder.add_virtual_bool_target_safe();
            world_state_revert_transitions.push(WorldStateRevertTransitionTarget {
                world_state_revert_proof,
                user_transaction,
                received_signature: (signature, validity),
                latest_account_process_proof,
                enabled,
            });
        }
        let old_world_state_root = builder.add_virtual_hash();

        let old_latest_account_root = builder.add_virtual_hash();

        let (new_world_state_root, new_latest_account_root) = verify_valid_approval_block::<F, H, D>(
            builder,
            current_block_number,
            &world_state_revert_transitions,
            old_world_state_root,
            old_latest_account_root,
        );

        Self {
            current_block_number,
            world_state_revert_transitions,
            old_world_state_root,
            new_world_state_root,
            old_latest_account_root,
            new_latest_account_root,
            log_max_n_users,
        }
    }

    /// Returns `(new_world_state_root, new_latest_account_root)`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &ApprovalBlockProduction<F>,
    ) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
        // assert!(!user_transactions.is_empty());

        let (new_world_state_root, new_latest_account_root) = witness.calculate();

        pw.set_hash_target(self.old_world_state_root, *witness.old_world_state_root);
        pw.set_hash_target(
            self.old_latest_account_root,
            *witness.old_latest_account_root,
        );

        pw.set_target(
            self.current_block_number,
            F::from_canonical_u32(witness.current_block_number),
        );
        for (t, w) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.world_state_revert_proofs.iter())
        {
            t.world_state_revert_proof.set_witness(pw, w);
        }

        let default_proof = SmtProcessProof::with_root(new_world_state_root);
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.world_state_revert_proofs.len())
        {
            t.world_state_revert_proof.set_witness(pw, &default_proof);
        }

        for (t, u) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.user_transactions.iter())
        {
            t.user_transaction.set_witness(pw, u);
        }
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.user_transactions.len())
        {
            t.user_transaction.set_witness(pw, &Default::default());
        }

        let default_signature = SimpleSignaturePublicInputs::new(4, 4);
        for (t, r) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.received_signatures.iter())
        {
            let r: Option<&_> = r.into();
            t.received_signature
                .0
                .set_witness(pw, r.unwrap_or(&default_signature));
            pw.set_bool_target(t.received_signature.1, r.is_some());
        }
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.received_signatures.len())
        {
            t.received_signature.0.set_witness(pw, &default_signature);
            pw.set_bool_target(t.received_signature.1, false);
        }

        for t in self
            .world_state_revert_transitions
            .iter()
            .take(witness.user_transactions.len())
        {
            pw.set_bool_target(t.enabled, true);
        }

        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.user_transactions.len())
        {
            pw.set_bool_target(t.enabled, false);
        }

        for (t, a) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.latest_account_tree_process_proofs.iter())
        {
            t.latest_account_process_proof.set_witness(pw, a);
        }

        let default_proof = SmtProcessProof::with_root(new_latest_account_root);
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.latest_account_tree_process_proofs.len())
        {
            t.latest_account_process_proof
                .set_witness(pw, &default_proof);
        }

        (new_world_state_root, new_latest_account_root)
    }
}

/// Returns `(old_world_state_root, new_world_state_root, old_account_tree_root, new_account_tree_root)`
#[allow(clippy::too_many_arguments)]
pub fn verify_valid_approval_block<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    current_block_number: Target,
    world_state_revert_transitions: &[WorldStateRevertTransitionTarget],
    old_world_state_root: HashOutTarget,
    old_latest_account_root: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let zero = builder.zero();

    // world state process proof と latest account process proof は正しい遷移になるように並んでいる.
    let mut prev_world_state_root = old_world_state_root;
    let mut prev_latest_account_root = old_latest_account_root;
    for WorldStateRevertTransitionTarget {
        world_state_revert_proof,
        latest_account_process_proof,
        ..
    } in world_state_revert_transitions
    {
        builder.connect_hashes(world_state_revert_proof.old_root, prev_world_state_root);
        builder.connect_hashes(
            latest_account_process_proof.old_root,
            prev_latest_account_root,
        );

        prev_world_state_root = world_state_revert_proof.new_root;
        prev_latest_account_root = latest_account_process_proof.new_root;
    }
    let new_world_state_root = prev_world_state_root;
    let new_latest_account_root = prev_latest_account_root;

    for WorldStateRevertTransitionTarget {
        world_state_revert_proof: w,
        user_transaction: u,
        received_signature: r,
        latest_account_process_proof: a,
        enabled,
        ..
    } in world_state_revert_transitions
    {
        let (signature, enabled_signature) = r;
        assert!(signature.message.len() <= 4);

        // 特定のメッセージに署名したことを確かめる.
        enforce_equal_if_enabled(
            builder,
            HashOutTarget::from_partial(&signature.message, zero),
            old_world_state_root, // = proposal_world_state_root
            *enabled_signature,
        );

        enforce_equal_if_enabled(builder, w.old_value, u.new_user_asset_root, *enabled);

        let expected_new_root = conditionally_select(
            builder,
            u.new_user_asset_root,
            u.middle_user_asset_root,
            *enabled_signature,
        );
        enforce_equal_if_enabled(builder, w.new_value, expected_new_root, *enabled);

        let old_last_block_number = a.old_value.elements[0];
        builder.connect(a.old_value.elements[1], zero);
        builder.connect(a.old_value.elements[2], zero);
        builder.connect(a.old_value.elements[3], zero);
        let new_last_block_number = a.new_value.elements[0];
        builder.connect(a.new_value.elements[1], zero);
        builder.connect(a.new_value.elements[2], zero);
        builder.connect(a.new_value.elements[3], zero);

        let expected_new_last_block_number = builder._if(
            *enabled_signature,
            current_block_number,
            old_last_block_number,
        );
        builder.connect(expected_new_last_block_number, new_last_block_number);
    }

    (new_world_state_root, new_latest_account_root)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        config::RollupConstants,
        rollup::{
            block::make_sample_circuit_inputs,
            gadgets::approval_block::ApprovalBlockProductionTarget,
        },
    };

    #[test]
    fn test_approval_block() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type H = <C as GenericConfig<D>>::InnerHasher;
        type F = <C as GenericConfig<D>>::F;
        let rollup_constants: RollupConstants = RollupConstants {
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
        let n_txs = 1 << rollup_constants.log_n_txs;
        let examples = make_sample_circuit_inputs::<C, D>(rollup_constants);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let approval_block_target = ApprovalBlockProductionTarget::add_virtual_to::<F, H, D>(
            &mut builder,
            rollup_constants.log_max_n_users,
            n_txs,
        );
        let circuit_data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        approval_block_target.set_witness::<F, D>(&mut pw, &examples[0].approval_block);

        println!("start proving: block_proof");
        let start = Instant::now();
        let proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        circuit_data.verify(proof).unwrap();
    }
}
