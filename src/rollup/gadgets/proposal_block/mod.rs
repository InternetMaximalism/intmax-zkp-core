use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    merkle_tree::gadgets::get_merkle_root_target_from_leaves,
    recursion::gadgets::RecursiveProofTarget,
    sparse_merkle_tree::{
        gadgets::{
            common::{conditionally_select, enforce_equal_if_enabled, logical_or},
            process::{
                process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
                utils::{get_process_merkle_proof_role, ProcessMerkleProofRoleTarget},
            },
        },
        proof::ProcessMerkleProofRole,
    },
};

use super::super::circuits::merge_and_purge::parse_merge_and_purge_public_inputs;

#[derive(Clone, Debug)]
pub struct ProposalBlockProofTarget<
    const D: usize,
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
    const N_TXS: usize,
> {
    pub world_state_process_proofs: [SparseMerkleProcessProofTarget<N_LOG_USERS>; N_TXS], // input

    pub user_tx_proofs: [RecursiveProofTarget<D>; N_TXS], // input

    pub block_tx_root: HashOutTarget, // output

    pub old_world_state_root: HashOutTarget, // input

    pub new_world_state_root: HashOutTarget, // output
}

impl<const D: usize, const N_LOG_USERS: usize, const N_LOG_TXS: usize, const N_TXS: usize>
    ProposalBlockProofTarget<D, N_LOG_USERS, N_LOG_TXS, N_TXS>
{
    #![cfg(not(doctest))]
    /// # Example
    ///
    /// ```
    /// let config = CircuitConfig::standard_recursion_config();
    /// let mut builder: CircuitBuilder<F, D> = CircuitBuilder::new(config);
    /// let proof_of_purge_t: PurgeTransitionTarget<N_LEVELS, N_DIFFS> =
    ///     PurgeTransitionTarget::add_virtual_to(&mut builder);
    /// builder.register_public_inputs(&proof_of_purge_t.new_user_asset_root.elements);
    /// let inner_circuit_data = builder.build::<C>();
    /// let block_target = ProposalBlockProofTarget::add_virtual_to::<F, H, C>(&mut builder, inner_circuit_data);
    /// ```
    pub fn add_virtual_to<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        builder: &mut CircuitBuilder<F, D>,
        inner_circuit_data: &CircuitData<F, C, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        assert_eq!(2usize.pow(N_LOG_TXS as u32), N_TXS);

        let mut world_state_process_proofs = vec![];
        for _ in 0..N_TXS {
            let a = SparseMerkleProcessProofTarget::add_virtual_to::<F, C::Hasher, D>(builder);
            world_state_process_proofs.push(a);
        }

        let mut user_tx_proofs = vec![];
        for _ in 0..N_TXS {
            let b = RecursiveProofTarget::add_virtual_to(builder, inner_circuit_data);
            user_tx_proofs.push(b);
        }

        let old_world_state_root = builder.add_virtual_hash();

        let (block_tx_root, new_world_state_root) =
            verify_valid_proposal_block::<F, C::Hasher, D, N_LOG_USERS, N_LOG_TXS>(
                builder,
                &world_state_process_proofs,
                &user_tx_proofs,
                old_world_state_root,
            );

        Self {
            world_state_process_proofs: world_state_process_proofs.try_into().unwrap(),
            user_tx_proofs: user_tx_proofs.try_into().unwrap(),
            block_tx_root,
            old_world_state_root,
            new_world_state_root,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        world_state_process_proofs: &[SmtProcessProof<F>],
        user_tx_proofs: &[ProofWithPublicInputs<F, C, D>],
        old_world_state_root: HashOut<F>,
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_hash_target(self.old_world_state_root, old_world_state_root);

        assert!(world_state_process_proofs.len() <= self.world_state_process_proofs.len());
        for (p_t, p) in self
            .world_state_process_proofs
            .iter()
            .zip(world_state_process_proofs.iter())
        {
            p_t.set_witness(pw, p);
        }

        let latest_root = world_state_process_proofs.last().unwrap().new_root;

        let default_hash_out = HashOut {
            elements: [F::ZERO; 4],
        };
        let default_proof = SmtProcessProof {
            old_root: latest_root,
            old_key: default_hash_out.into(),
            old_value: default_hash_out.into(),
            new_root: latest_root,
            new_key: default_hash_out.into(),
            new_value: default_hash_out.into(),
            siblings: vec![],
            is_old0: true,
            fnc: ProcessMerkleProofRole::ProcessNoOp,
        };
        for p_t in self
            .world_state_process_proofs
            .iter()
            .skip(world_state_process_proofs.len())
        {
            p_t.set_witness(pw, &default_proof);
        }

        assert!(user_tx_proofs.len() <= self.user_tx_proofs.len());
        for (r_t, r) in self.user_tx_proofs.iter().zip(user_tx_proofs.iter()) {
            r_t.set_witness(pw, &r.clone(), true);
        }

        for r_t in self.user_tx_proofs.iter().skip(user_tx_proofs.len()) {
            r_t.set_witness(pw, &user_tx_proofs.last().unwrap().clone(), false);
        }
    }
}

/// Returns `(block_tx_root, old_world_state_root, new_world_state_root)`
pub fn verify_valid_proposal_block<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    world_state_process_proofs: &[SparseMerkleProcessProofTarget<N_LOG_USERS>],
    user_tx_proofs: &[RecursiveProofTarget<D>],
    old_world_state_root: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let constant_true = builder._true();
    let constant_false = builder._false();
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    // world state process proof は正しい遷移になるように並んでいる.
    let mut new_world_state_root = old_world_state_root;
    for proof in world_state_process_proofs {
        let fnc = get_process_merkle_proof_role(builder, proof.fnc);
        enforce_equal_if_enabled(
            builder,
            proof.old_root,
            new_world_state_root,
            fnc.is_not_no_op,
        );

        new_world_state_root = proof.new_root;
    }

    // 各 user asset root は world state tree に含まれていることの検証.
    for (w, u) in world_state_process_proofs.iter().zip(user_tx_proofs.iter()) {
        let public_inputs = parse_merge_and_purge_public_inputs(&u.inner.0.public_inputs);
        let old_user_asset_root = public_inputs.middle_user_asset_root;
        let new_user_asset_root = public_inputs.new_user_asset_root;

        let ProcessMerkleProofRoleTarget {
            is_no_op,
            is_insert_op,
            is_update_op,
            is_remove_op,
            ..
        } = get_process_merkle_proof_role(builder, w.fnc);

        // If user transaction is not enabled, corresponding process proof is for noop process.
        let is_no_op_or_enabled = logical_or(builder, is_no_op, u.enabled);
        builder.connect(is_no_op_or_enabled.target, constant_true.target);

        // 古い world state には古い user asset root が格納されている
        enforce_equal_if_enabled(builder, old_user_asset_root, w.old_value, u.enabled);

        // purge では world state への insert は行われない
        builder.connect(is_insert_op.target, constant_false.target);

        let is_update_op_and_enabled = builder.and(is_update_op, u.enabled);
        enforce_equal_if_enabled(
            builder,
            new_user_asset_root,
            w.new_value,
            is_update_op_and_enabled,
        );
        let is_remove_op_and_enabled = builder.and(is_remove_op, u.enabled);
        enforce_equal_if_enabled(
            builder,
            new_user_asset_root,
            default_hash,
            is_remove_op_and_enabled,
        );
        let is_no_op_and_enabled = builder.and(is_no_op, u.enabled);
        enforce_equal_if_enabled(
            builder,
            new_user_asset_root,
            old_user_asset_root,
            is_no_op_and_enabled,
        );
    }

    // block tx root は block_txs から生まれる Merkle tree の root である.
    let mut leaves = vec![];
    for proof in user_tx_proofs {
        let public_inputs = parse_merge_and_purge_public_inputs(&proof.inner.0.public_inputs);
        let leaf =
            conditionally_select(builder, public_inputs.tx_hash, default_hash, proof.enabled);

        leaves.push(leaf);
    }

    let block_tx_root = get_merkle_root_target_from_leaves::<F, H, D>(builder, leaves);

    (block_tx_root, new_world_state_root)
}
