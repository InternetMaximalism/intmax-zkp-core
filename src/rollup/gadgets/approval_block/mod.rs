use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    recursion::gadgets::RecursiveProofTarget,
    sparse_merkle_tree::{
        gadgets::{
            common::{enforce_equal_if_enabled, is_equal_hash_out},
            process::process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
        },
        proof::ProcessMerkleProofRole,
    },
};

use super::super::circuits::merge_and_purge::parse_merge_and_purge_public_inputs;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedMessage<F: RichField> {
    message: HashOut<F>,
    public_key: HashOut<F>,
    signature: HashOut<F>,
}

#[derive(Clone, Debug)]
pub struct ApprovalBlockProofTarget<
    const D: usize,
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
    const N_TXS: usize,
> {
    pub current_block_number: Target,

    pub world_state_revert_proofs: [SparseMerkleProcessProofTarget<N_LOG_USERS>; N_TXS],

    pub user_tx_proofs: [RecursiveProofTarget<D>; N_TXS],

    pub received_signatures: [RecursiveProofTarget<D>; N_TXS],

    pub account_tree_process_proofs: [SparseMerkleProcessProofTarget<N_LOG_USERS>; N_TXS],

    pub old_world_state_root: HashOutTarget,

    pub new_world_state_root: HashOutTarget,

    pub old_account_tree_root: HashOutTarget,

    pub new_account_tree_root: HashOutTarget,
}

impl<const D: usize, const N_LOG_USERS: usize, const N_LOG_TXS: usize, const N_TXS: usize>
    ApprovalBlockProofTarget<D, N_LOG_USERS, N_LOG_TXS, N_TXS>
{
    #![cfg(not(doctest))]
    /// # Example
    ///
    /// ```
    /// let config = CircuitConfig::standard_recursion_config();
    /// let mut builder: CircuitBuilder<F, D> = CircuitBuilder::new(config.clone());
    /// let proof_of_purge_t: PurgeTransitionTarget<N_LEVELS, N_DIFFS> =
    ///     PurgeTransitionTarget::add_virtual_to(&mut builder);
    /// builder.register_public_inputs(&proof_of_purge_t.new_user_asset_root.elements);
    /// let inner_circuit_data = builder.build::<C>();
    ///
    /// let mut builder: CircuitBuilder<F, D> = CircuitBuilder::new(config.clone());
    /// let target = SimpleSignatureTarget::add_virtual_to::<F, H, D>(&mut builder);
    /// builder.register_public_inputs(&target.message.elements);
    /// builder.register_public_inputs(&target.public_key.elements);
    /// builder.register_public_inputs(&target.signature.elements);
    /// let zkdsa_circuit_data = builder.build::<C>();
    /// let block_target = ApprovalBlockProofTarget::add_virtual_to::<F, H, C>(&mut builder, inner_circuit_data, zkdsa_circuit_data);
    /// dbg!(block_target);
    /// ```
    pub fn add_virtual_to<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        builder: &mut CircuitBuilder<F, D>,
        user_tx_circuit_data: &CircuitData<F, C, D>,
        zkdsa_circuit_data: &CircuitData<F, C, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let current_block_number = builder.add_virtual_target();

        let mut world_state_revert_proofs = vec![];
        for _ in 0..N_TXS {
            let a = SparseMerkleProcessProofTarget::add_virtual_to::<F, C::Hasher, D>(builder);
            world_state_revert_proofs.push(a);
        }

        let mut user_tx_proofs = vec![];
        for _ in 0..N_TXS {
            let b = RecursiveProofTarget::add_virtual_to(builder, user_tx_circuit_data);
            user_tx_proofs.push(b);
        }

        let mut received_signatures = vec![];
        for _ in 0..N_TXS {
            let c = RecursiveProofTarget::add_virtual_to(builder, zkdsa_circuit_data);
            received_signatures.push(c);
        }

        let mut account_tree_process_proofs = vec![];
        for _ in 0..N_TXS {
            let d = SparseMerkleProcessProofTarget::add_virtual_to::<F, C::Hasher, D>(builder);
            account_tree_process_proofs.push(d);
        }

        let (
            old_world_state_root,
            new_world_state_root,
            old_account_tree_root,
            new_account_tree_root,
        ) = verify_valid_approval_block::<F, C::Hasher, D, N_LOG_USERS, N_LOG_TXS>(
            builder,
            current_block_number,
            &world_state_revert_proofs,
            &user_tx_proofs,
            &received_signatures,
            &account_tree_process_proofs,
        );

        Self {
            current_block_number,
            world_state_revert_proofs: world_state_revert_proofs.try_into().unwrap(),
            user_tx_proofs: user_tx_proofs.try_into().unwrap(),
            received_signatures: received_signatures.try_into().unwrap(),
            account_tree_process_proofs: account_tree_process_proofs.try_into().unwrap(),
            old_world_state_root,
            new_world_state_root,
            old_account_tree_root,
            new_account_tree_root,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        current_block_number: u32,
        world_state_revert_proofs: &[SmtProcessProof<F>],
        user_tx_proofs: &[ProofWithPublicInputs<F, C, D>],
        received_signatures: &[ProofWithPublicInputs<F, C, D>],
        account_tree_process_proofs: &[SmtProcessProof<F>],
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_target(
            self.current_block_number,
            F::from_canonical_u32(current_block_number),
        );
        assert!(world_state_revert_proofs.len() <= self.world_state_revert_proofs.len(),);
        for (p_t, p) in self
            .world_state_revert_proofs
            .iter()
            .zip(world_state_revert_proofs.iter())
        {
            p_t.set_witness(pw, p);
        }

        let new_world_state_root = world_state_revert_proofs.last().unwrap().new_root;

        let default_hash_out = HashOut {
            elements: [F::ZERO; 4],
        };
        let default_proof = SmtProcessProof {
            old_root: new_world_state_root,
            old_key: default_hash_out.into(),
            old_value: default_hash_out.into(),
            new_root: new_world_state_root,
            new_key: default_hash_out.into(),
            new_value: default_hash_out.into(),
            siblings: vec![],
            is_old0: true,
            fnc: ProcessMerkleProofRole::ProcessNoOp,
        };
        for p_t in self
            .world_state_revert_proofs
            .iter()
            .skip(world_state_revert_proofs.len())
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

        assert!(received_signatures.len() <= self.received_signatures.len());
        for (r_t, r) in self
            .received_signatures
            .iter()
            .zip(received_signatures.iter())
        {
            r_t.set_witness(pw, r, true);
        }
        for r_t in self
            .received_signatures
            .iter()
            .skip(received_signatures.len())
        {
            r_t.set_witness(pw, received_signatures.last().unwrap(), false);
        }

        assert!(account_tree_process_proofs.len() <= self.account_tree_process_proofs.len());
        for (p_t, p) in self
            .account_tree_process_proofs
            .iter()
            .zip(account_tree_process_proofs.iter())
        {
            p_t.set_witness(pw, p);
        }

        let new_account_tree_root = account_tree_process_proofs.last().unwrap().new_root;

        let default_hash_out = HashOut {
            elements: [F::ZERO; 4],
        };
        let default_proof = SmtProcessProof {
            old_root: new_account_tree_root,
            old_key: default_hash_out.into(),
            old_value: default_hash_out.into(),
            new_root: new_account_tree_root,
            new_key: default_hash_out.into(),
            new_value: default_hash_out.into(),
            siblings: vec![],
            is_old0: true,
            fnc: ProcessMerkleProofRole::ProcessNoOp,
        };
        for p_t in self
            .account_tree_process_proofs
            .iter()
            .skip(account_tree_process_proofs.len())
        {
            p_t.set_witness(pw, &default_proof);
        }
    }
}

/// Returns `(old_world_state_root, new_world_state_root, old_account_tree_root, new_account_tree_root)`
pub fn verify_valid_approval_block<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    current_block_number: Target,
    world_state_revert_proofs: &[SparseMerkleProcessProofTarget<N_LOG_USERS>],
    user_tx_proofs: &[RecursiveProofTarget<D>],
    received_signatures: &[RecursiveProofTarget<D>],
    account_tree_process_proofs: &[SparseMerkleProcessProofTarget<N_LOG_USERS>],
) -> (HashOutTarget, HashOutTarget, HashOutTarget, HashOutTarget) {
    let zero = builder.zero();

    // world state process proof と latest account process proof は正しい遷移になるように並んでいる.
    let mut prev_world_state_root = world_state_revert_proofs[0].new_root;
    let mut prev_account_tree_root = account_tree_process_proofs[0].new_root;
    for ((world_state_revert_proof, account_tree_process_proof), received_signature) in
        world_state_revert_proofs
            .iter()
            .zip(account_tree_process_proofs.iter())
            .zip(received_signatures.iter())
            .skip(1)
    {
        enforce_equal_if_enabled(
            builder,
            world_state_revert_proof.old_root,
            prev_world_state_root,
            received_signature.enabled,
        );
        enforce_equal_if_enabled(
            builder,
            account_tree_process_proof.old_root,
            prev_account_tree_root,
            received_signature.enabled,
        );

        prev_world_state_root = world_state_revert_proof.new_root;
        prev_account_tree_root = account_tree_process_proof.new_root;
    }
    let old_world_state_root = world_state_revert_proofs.first().unwrap().old_root;
    let new_world_state_root = world_state_revert_proofs.last().unwrap().new_root;
    let old_account_tree_root = account_tree_process_proofs.first().unwrap().old_root;
    let new_account_tree_root = account_tree_process_proofs.last().unwrap().new_root;

    for (((w, u), r), a) in world_state_revert_proofs
        .iter()
        .zip(user_tx_proofs.iter())
        .zip(received_signatures.iter())
        .zip(account_tree_process_proofs.iter())
    {
        // signature is enabled <=> user asset root is not reverted
        let enabled_signature = r.enabled;
        let is_not_reverted = {
            let tmp = is_equal_hash_out(builder, w.new_root, w.old_root);

            builder.and(tmp, u.enabled)
        };
        builder.connect(enabled_signature.target, is_not_reverted.target);

        let public_inputs = parse_merge_and_purge_public_inputs(&u.inner.public_inputs);
        enforce_equal_if_enabled(
            builder,
            w.old_root,
            public_inputs.new_user_asset_root,
            u.enabled,
        );
        let is_reverted =
            is_equal_hash_out(builder, w.new_root, public_inputs.middle_user_asset_root);
        let is_not_reverted = is_equal_hash_out(builder, w.new_root, w.old_root);
        let is_not_not_reverted = builder.not(is_not_reverted);
        enforce_equal_if_enabled(
            builder,
            HashOutTarget::from_partial(&[is_reverted.target], zero),
            HashOutTarget::from_partial(&[is_not_not_reverted.target], zero),
            u.enabled,
        );

        let old_last_block_number = a.old_value.elements[0];
        builder.connect(a.old_value.elements[1], zero); // TODO: transaction index を入れる？
        builder.connect(a.old_value.elements[2], zero);
        builder.connect(a.old_value.elements[3], zero);
        let new_last_block_number = a.new_value.elements[0];
        builder.connect(a.new_value.elements[1], zero);
        builder.connect(a.new_value.elements[2], zero);
        builder.connect(a.new_value.elements[3], zero);

        let expected_new_last_block_number = builder._if(
            enabled_signature,
            current_block_number,
            old_last_block_number,
        );
        builder.connect(expected_new_last_block_number, new_last_block_number);
    }

    (
        old_world_state_root,
        new_world_state_root,
        old_account_tree_root,
        new_account_tree_root,
    )
}
