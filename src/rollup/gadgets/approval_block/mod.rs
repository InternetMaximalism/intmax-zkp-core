use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    recursion::gadgets::RecursiveProofTarget,
    sparse_merkle_tree::gadgets::{
        common::{enforce_equal_if_enabled, is_equal_hash_out},
        process::process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
    },
    transaction::circuits::{
        MergeAndPurgeTransitionPublicInputs, MergeAndPurgeTransitionPublicInputsTarget,
    },
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedMessage<F: RichField> {
    message: HashOut<F>,
    public_key: HashOut<F>,
    signature: HashOut<F>,
}

#[derive(Clone)]
pub struct ApprovalBlockProofTarget<
    const D: usize,
    const N_LOG_USERS: usize, // N_LOG_MAX_USERS
    const N_TXS: usize,
> {
    pub current_block_number: Target,

    pub world_state_revert_proofs: [SparseMerkleProcessProofTarget<N_LOG_USERS>; N_TXS],

    pub user_transactions: [MergeAndPurgeTransitionPublicInputsTarget; N_TXS],

    pub received_signatures: [RecursiveProofTarget<D>; N_TXS],

    pub latest_account_tree_process_proofs: [SparseMerkleProcessProofTarget<N_LOG_USERS>; N_TXS],

    pub enabled_list: [BoolTarget; N_TXS],

    pub old_world_state_root: HashOutTarget,

    pub new_world_state_root: HashOutTarget,

    pub old_account_tree_root: HashOutTarget,

    pub new_account_tree_root: HashOutTarget,
}

impl<const D: usize, const N_LOG_USERS: usize, const N_TXS: usize>
    ApprovalBlockProofTarget<D, N_LOG_USERS, N_TXS>
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
        // user_tx_circuit_data: &'a CircuitData<F, C, D>,
        simple_signature_circuit_data: &CircuitData<F, C, D>,
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

        let mut user_transactions = vec![];
        for _ in 0..N_TXS {
            let b = MergeAndPurgeTransitionPublicInputsTarget::add_virtual_to(builder);
            user_transactions.push(b);
        }

        let mut received_signatures = vec![];
        for _ in 0..N_TXS {
            let c = RecursiveProofTarget::add_virtual_to(builder, simple_signature_circuit_data);
            received_signatures.push(c);
        }

        let mut latest_account_tree_process_proofs = vec![];
        for _ in 0..N_TXS {
            let d = SparseMerkleProcessProofTarget::add_virtual_to::<F, C::Hasher, D>(builder);
            latest_account_tree_process_proofs.push(d);
        }

        let mut enabled_list = vec![];
        for _ in 0..N_TXS {
            enabled_list.push(builder.add_virtual_bool_target_safe());
        }

        let (
            old_world_state_root,
            new_world_state_root,
            old_account_tree_root,
            new_account_tree_root,
        ) = verify_valid_approval_block::<F, C::Hasher, D, N_LOG_USERS>(
            builder,
            current_block_number,
            &world_state_revert_proofs,
            &user_transactions,
            &received_signatures,
            &latest_account_tree_process_proofs,
            &enabled_list,
        );

        Self {
            current_block_number,
            world_state_revert_proofs: world_state_revert_proofs.try_into().unwrap(),
            user_transactions: user_transactions
                .try_into()
                .map_err(|_| anyhow::anyhow!("fail to convert vector to constant size array"))
                .unwrap(),
            received_signatures: received_signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("fail to convert vector to constant size array"))
                .unwrap(),
            latest_account_tree_process_proofs: latest_account_tree_process_proofs
                .try_into()
                .unwrap(),
            enabled_list: enabled_list.try_into().unwrap(),
            old_world_state_root,
            new_world_state_root,
            old_account_tree_root,
            new_account_tree_root,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        current_block_number: u32,
        world_state_revert_proofs: &[SmtProcessProof<F>],
        user_transactions: &[MergeAndPurgeTransitionPublicInputs<F>],
        received_signatures: &[Option<ProofWithPublicInputs<F, C, D>>],
        default_simple_signature: &ProofWithPublicInputs<F, C, D>,
        latest_account_tree_process_proofs: &[SmtProcessProof<F>],
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        assert!(!user_transactions.is_empty());
        assert!(user_transactions.len() <= self.user_transactions.len());
        assert_eq!(world_state_revert_proofs.len(), user_transactions.len());
        assert_eq!(received_signatures.len(), user_transactions.len());
        assert_eq!(
            latest_account_tree_process_proofs.len(),
            user_transactions.len()
        );

        pw.set_target(
            self.current_block_number,
            F::from_canonical_u32(current_block_number),
        );
        for (p_t, p) in self
            .world_state_revert_proofs
            .iter()
            .zip(world_state_revert_proofs.iter())
        {
            p_t.set_witness(pw, p);
        }

        let new_world_state_root = world_state_revert_proofs.last().unwrap().new_root;

        let default_proof = SmtProcessProof::with_root(new_world_state_root);
        for p_t in self
            .world_state_revert_proofs
            .iter()
            .skip(world_state_revert_proofs.len())
        {
            p_t.set_witness(pw, &default_proof);
        }

        for (r_t, r) in self.user_transactions.iter().zip(user_transactions.iter()) {
            r_t.set_witness(pw, r);
        }
        let last_user_transaction = user_transactions.last().unwrap();
        for r_t in self.user_transactions.iter().skip(user_transactions.len()) {
            r_t.set_witness(pw, last_user_transaction);
        }

        for (r_t, r) in self
            .received_signatures
            .iter()
            .zip(received_signatures.iter())
        {
            let r: Option<&_> = r.into();
            r_t.set_witness(pw, r.unwrap_or(default_simple_signature), r.is_some());
        }
        for r_t in self
            .received_signatures
            .iter()
            .skip(received_signatures.len())
        {
            r_t.set_witness(pw, default_simple_signature, false);
        }

        for enabled_t in self.enabled_list.iter().take(user_transactions.len()) {
            pw.set_bool_target(*enabled_t, true);
        }

        for enabled_t in self.enabled_list.iter().skip(user_transactions.len()) {
            pw.set_bool_target(*enabled_t, false);
        }

        for (p_t, p) in self
            .latest_account_tree_process_proofs
            .iter()
            .zip(latest_account_tree_process_proofs.iter())
        {
            p_t.set_witness(pw, p);
        }

        let new_account_tree_root = latest_account_tree_process_proofs.last().unwrap().new_root;

        let default_proof = SmtProcessProof::with_root(new_account_tree_root);
        for p_t in self
            .latest_account_tree_process_proofs
            .iter()
            .skip(latest_account_tree_process_proofs.len())
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
>(
    builder: &mut CircuitBuilder<F, D>,
    current_block_number: Target,
    world_state_revert_proofs: &[SparseMerkleProcessProofTarget<N_LOG_USERS>],
    user_transactions: &[MergeAndPurgeTransitionPublicInputsTarget],
    received_signatures: &[RecursiveProofTarget<D>],
    latest_account_tree_process_proofs: &[SparseMerkleProcessProofTarget<N_LOG_USERS>],
    enabled_list: &[BoolTarget],
) -> (HashOutTarget, HashOutTarget, HashOutTarget, HashOutTarget) {
    let zero = builder.zero();

    // world state process proof と latest account process proof は正しい遷移になるように並んでいる.
    let mut prev_world_state_root = world_state_revert_proofs[0].new_root;
    let mut prev_account_tree_root = latest_account_tree_process_proofs[0].new_root;
    for ((world_state_revert_proof, account_tree_process_proof), received_signature) in
        world_state_revert_proofs
            .iter()
            .zip(latest_account_tree_process_proofs.iter())
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
    let old_account_tree_root = latest_account_tree_process_proofs.first().unwrap().old_root;
    let new_account_tree_root = latest_account_tree_process_proofs.last().unwrap().new_root;

    for ((((w, u), r), a), enabled) in world_state_revert_proofs
        .iter()
        .zip_eq(user_transactions)
        .zip_eq(received_signatures)
        .zip_eq(latest_account_tree_process_proofs)
        .zip_eq(enabled_list.iter().cloned())
    {
        // signature is enabled <=> user asset root is not reverted
        let enabled_signature = r.enabled;
        let is_not_reverted = {
            let tmp = is_equal_hash_out(builder, w.new_root, w.old_root);

            builder.and(tmp, enabled)
        };
        builder.connect(enabled_signature.target, is_not_reverted.target);

        enforce_equal_if_enabled(builder, w.old_root, u.new_user_asset_root, enabled);
        let is_reverted = is_equal_hash_out(builder, w.new_root, u.middle_user_asset_root);
        let is_not_reverted = is_equal_hash_out(builder, w.new_root, w.old_root);
        let is_not_not_reverted = builder.not(is_not_reverted);
        enforce_equal_if_enabled(
            builder,
            HashOutTarget::from_partial(&[is_reverted.target], zero),
            HashOutTarget::from_partial(&[is_not_not_reverted.target], zero),
            enabled,
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

#[test]
fn test_approval_block() {
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };

    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        merkle_tree::tree::get_merkle_proof,
        sparse_merkle_tree::{
            goldilocks_poseidon::{
                GoldilocksHashOut, LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory,
                PoseidonSparseMerkleTree, WrappedHashOut,
            },
            proof::SparseMerkleInclusionProof,
        },
        transaction::{
            block_header::{get_block_hash, BlockHeader},
            circuits::make_user_proof_circuit,
            gadgets::merge::MergeProof,
        },
        zkdsa::{account::private_key_to_account, circuits::make_simple_signature_circuit},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const N_LOG_MAX_USERS: usize = 3;
    const N_LOG_MAX_TXS: usize = 3;
    const N_LOG_MAX_CONTRACTS: usize = 3;
    const N_LOG_MAX_VARIABLES: usize = 3;
    const N_LOG_TXS: usize = 2;
    const N_LOG_RECIPIENTS: usize = 3;
    const N_LOG_CONTRACTS: usize = 3;
    const N_LOG_VARIABLES: usize = 3;
    const N_DIFFS: usize = 2;
    const N_MERGES: usize = 2;
    const N_TXS: usize = 2usize.pow(N_LOG_TXS as u32);

    let mut world_state_tree = PoseidonSparseMerkleTree::new(
        Arc::new(Mutex::new(NodeDataMemory::default())),
        Default::default(),
    );

    let merge_and_purge_circuit = make_user_proof_circuit::<
        F,
        C,
        D,
        N_LOG_MAX_USERS,
        N_LOG_MAX_TXS,
        N_LOG_MAX_CONTRACTS,
        N_LOG_MAX_VARIABLES,
        N_LOG_TXS,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_DIFFS,
        N_MERGES,
    >();

    // dbg!(&purge_proof_circuit_data.common);

    let sender1_private_key = HashOut {
        elements: [
            GoldilocksField::from_canonical_u64(17426287337377512978),
            GoldilocksField::from_canonical_u64(8703645504073070742),
            GoldilocksField::from_canonical_u64(11984317793392655464),
            GoldilocksField::from_canonical_u64(9979414176933652180),
        ],
    };
    let sender1_account = private_key_to_account(sender1_private_key);
    let sender1_address = sender1_account.address.0;

    let mut sender1_user_asset_tree: LayeredLayeredPoseidonSparseMerkleTree<NodeDataMemory> =
        LayeredLayeredPoseidonSparseMerkleTree::new(Default::default(), Default::default());

    let mut sender1_tx_diff_tree: LayeredLayeredPoseidonSparseMerkleTree<NodeDataMemory> =
        LayeredLayeredPoseidonSparseMerkleTree::new(Default::default(), Default::default());

    let key1 = (
        GoldilocksHashOut::from_u128(12),
        GoldilocksHashOut::from_u128(305),
        GoldilocksHashOut::from_u128(8012),
    );
    let value1 = GoldilocksHashOut::from_u128(2053);
    let key2 = (
        GoldilocksHashOut::from_u128(12),
        GoldilocksHashOut::from_u128(471),
        GoldilocksHashOut::from_u128(8012),
    );
    let value2 = GoldilocksHashOut::from_u128(1111);

    let key3 = (
        GoldilocksHashOut::from_u128(407),
        GoldilocksHashOut::from_u128(305),
        GoldilocksHashOut::from_u128(8012),
    );
    let value3 = GoldilocksHashOut::from_u128(2053);
    let key4 = (
        GoldilocksHashOut::from_u128(832),
        GoldilocksHashOut::from_u128(471),
        GoldilocksHashOut::from_u128(8012),
    );
    let value4 = GoldilocksHashOut::from_u128(1111);

    let zero = GoldilocksHashOut::from_u128(0);
    sender1_user_asset_tree
        .set(key1.0, key1.1, key1.2, value1)
        .unwrap();
    sender1_user_asset_tree
        .set(key2.0, key2.1, key2.2, value2)
        .unwrap();

    world_state_tree
        .set(
            sender1_account.address.0.into(),
            sender1_user_asset_tree.get_root(),
        )
        .unwrap();

    let proof1 = sender1_user_asset_tree
        .set(key2.0, key2.1, key2.2, zero)
        .unwrap();
    let proof2 = sender1_user_asset_tree
        .set(key1.0, key1.1, key1.2, zero)
        .unwrap();

    let proof3 = sender1_tx_diff_tree
        .set(key3.0, key3.1, key3.2, value3)
        .unwrap();
    let proof4 = sender1_tx_diff_tree
        .set(key4.0, key4.1, key4.2, value4)
        .unwrap();

    let sender1_input_witness = vec![proof1, proof2];
    let sender1_output_witness = vec![proof3, proof4];

    let sender2_private_key = HashOut {
        elements: [
            GoldilocksField::from_canonical_u64(15657143458229430356),
            GoldilocksField::from_canonical_u64(6012455030006979790),
            GoldilocksField::from_canonical_u64(4280058849535143691),
            GoldilocksField::from_canonical_u64(5153662694263190591),
        ],
    };
    dbg!(&sender2_private_key);
    let sender2_account = private_key_to_account(sender2_private_key);
    let sender2_address = sender2_account.address.0;

    let node_data = Arc::new(Mutex::new(NodeDataMemory::default()));
    let mut sender2_user_asset_tree =
        PoseidonSparseMerkleTree::new(node_data.clone(), Default::default());

    let mut sender2_tx_diff_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(node_data.clone(), Default::default());

    let mut deposit_sender2_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(node_data, Default::default());

    deposit_sender2_tree
        .set(sender2_address.into(), key1.1, key1.2, value1)
        .unwrap();
    deposit_sender2_tree
        .set(sender2_address.into(), key2.1, key2.2, value2)
        .unwrap();

    let deposit_sender2_tree: PoseidonSparseMerkleTree<NodeDataMemory> =
        deposit_sender2_tree.into();

    let merge_inclusion_proof2 = deposit_sender2_tree.find(&sender2_address.into()).unwrap();

    let deposit_nonce = HashOut::ZERO;
    let deposit_tx_hash =
        PoseidonHash::two_to_one(*merge_inclusion_proof2.root, deposit_nonce);

    let merge_inclusion_proof1 = get_merkle_proof(&[deposit_tx_hash.into()], 0, N_LOG_TXS);

    let default_hash = HashOut::ZERO;
    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
        let default_merkle_root = get_merkle_proof(&[], 0, N_LOG_TXS).root;
    let prev_block_header = BlockHeader {
        block_number: 0,
        prev_block_header_digest: default_hash,
        transactions_digest: *default_merkle_root,
        deposit_digest: *merge_inclusion_proof1.root,
        proposed_world_state_digest: default_hash,
        approved_world_state_digest: default_hash,
        latest_account_digest: default_hash,
    };

    let block_hash = get_block_hash(&prev_block_header);

    let deposit_merge_key = PoseidonHash::two_to_one(deposit_tx_hash, block_hash).into();

    let merge_process_proof = sender2_user_asset_tree
        .set(deposit_merge_key, merge_inclusion_proof2.value)
        .unwrap();

    let merge_proof = MergeProof {
        is_deposit: true,
        diff_tree_inclusion_proof: (
            prev_block_header,
            merge_inclusion_proof1,
            merge_inclusion_proof2,
        ),
        merge_process_proof,
        latest_account_tree_inclusion_proof: default_inclusion_proof,
        nonce: deposit_nonce.into(),
    };

    world_state_tree
        .set(sender2_address.into(), sender2_user_asset_tree.get_root())
        .unwrap();

    let mut sender2_user_asset_tree: LayeredLayeredPoseidonSparseMerkleTree<NodeDataMemory> =
        sender2_user_asset_tree.into();
    let proof1 = sender2_user_asset_tree
        .set(deposit_merge_key, key2.1, key2.2, zero)
        .unwrap();
    let proof2 = sender2_user_asset_tree
        .set(deposit_merge_key, key1.1, key1.2, zero)
        .unwrap();

    let proof3 = sender2_tx_diff_tree
        .set(key3.0, key3.1, key3.2, value3)
        .unwrap();
    let proof4 = sender2_tx_diff_tree
        .set(key4.0, key4.1, key4.2, value4)
        .unwrap();

    let sender2_input_witness = vec![proof1, proof2];
    let sender2_output_witness = vec![proof3, proof4];
    // dbg!(
    //     serde_json::to_string(&sender2_input_witness).unwrap(),
    //     serde_json::to_string(&sender2_output_witness).unwrap()
    // );

    let sender1_nonce = WrappedHashOut::rand();

    let mut pw = PartialWitness::new();
    merge_and_purge_circuit
        .targets
        .merge_proof_target
        .set_witness(
            &mut pw,
            &[],
            *sender1_input_witness.first().unwrap().0.old_root,
        );
    merge_and_purge_circuit
        .targets
        .purge_proof_target
        .set_witness(
            &mut pw,
            sender1_account.address,
            &sender1_input_witness,
            &sender1_output_witness,
            sender1_input_witness.first().unwrap().0.old_root,
            sender1_nonce,
        );

    println!("start proving: sender1_tx_proof");
    let start = Instant::now();
    let sender1_tx_proof = merge_and_purge_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender1_tx_proof.public_inputs);

    match merge_and_purge_circuit.verify(sender1_tx_proof.clone()) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }

    let sender2_nonce = WrappedHashOut::rand();

    let mut pw = PartialWitness::new();
    merge_and_purge_circuit
        .targets
        .merge_proof_target
        .set_witness(&mut pw, &[merge_proof], default_hash);
    merge_and_purge_circuit
        .targets
        .purge_proof_target
        .set_witness(
            &mut pw,
            sender2_account.address,
            &sender2_input_witness,
            &sender2_output_witness,
            sender2_input_witness.first().unwrap().0.old_root,
            sender2_nonce,
        );

    println!("start proving: sender2_tx_proof");
    let start = Instant::now();
    let sender2_tx_proof = merge_and_purge_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender2_tx_proof.public_inputs);

    match merge_and_purge_circuit.verify(sender2_tx_proof.clone()) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }

    let mut world_state_process_proofs = vec![];
    let mut user_tx_proofs = vec![];

    let sender1_world_state_process_proof = world_state_tree
        .set(sender1_address.into(), sender1_user_asset_tree.get_root())
        .unwrap();

    // dbg!(serde_json::to_string(&sender1_world_state_process_proof).unwrap());

    let sender2_world_state_process_proof = world_state_tree
        .set(sender2_address.into(), sender2_user_asset_tree.get_root())
        .unwrap();

    world_state_process_proofs.push(sender1_world_state_process_proof);
    user_tx_proofs.push(sender1_tx_proof.clone());
    world_state_process_proofs.push(sender2_world_state_process_proof);
    user_tx_proofs.push(sender2_tx_proof.clone());

    let zkdsa_circuit = make_simple_signature_circuit();

    let mut pw = PartialWitness::new();
    zkdsa_circuit.targets.set_witness(
        &mut pw,
        sender1_account.private_key,
        *world_state_tree.get_root(),
    );

    println!("start proving: sender1_received_signature");
    let start = Instant::now();
    let sender1_received_signature = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender1_received_signature.public_inputs);

    let mut pw = PartialWitness::new();
    zkdsa_circuit.targets.set_witness(
        &mut pw,
        sender2_account.private_key,
        *world_state_tree.get_root(),
    );

    println!("start proving: sender2_received_signature");
    let start = Instant::now();
    let sender2_received_signature = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender2_received_signature.public_inputs);

    let mut pw = PartialWitness::new();
    zkdsa_circuit
        .targets
        .set_witness(&mut pw, Default::default(), Default::default());

    println!("start proving: default_simple_signature");
    let start = Instant::now();
    let default_simple_signature = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let approval_block_target: ApprovalBlockProofTarget<D, N_LOG_MAX_USERS, N_TXS> =
        ApprovalBlockProofTarget::add_virtual_to(&mut builder, &zkdsa_circuit.data);
    let circuit_data = builder.build::<C>();

    let block_number = 1;

    let accounts_in_block: Vec<(Option<_>, _)> = vec![
        (Some(sender1_received_signature), sender1_tx_proof),
        (Some(sender2_received_signature), sender2_tx_proof),
    ];

    let mut latest_account_tree: PoseidonSparseMerkleTree<NodeDataMemory> =
        PoseidonSparseMerkleTree::new(Default::default(), Default::default());

    // NOTICE: merge proof の中に deposit が混ざっていると, revert proof がうまく出せない場合がある.
    // deposit してそれを消費して old: 0 -> middle: non-zero -> new: 0 となった場合は,
    // u.enabled かつ w.fnc == NoOp だが revert ではない.
    let mut world_state_revert_proofs = vec![];
    let mut latest_account_tree_process_proofs = vec![];
    let mut received_signatures = vec![];
    for (opt_received_signature, user_tx_proof) in accounts_in_block {
        let user_address = user_tx_proof.public_inputs.sender_address;
        let (last_block_number, confirmed_user_asset_root) = if opt_received_signature.is_none() {
            let old_block_number = latest_account_tree.get(&user_address.0.into()).unwrap();
            (
                old_block_number.to_u32(),
                user_tx_proof.public_inputs.old_user_asset_root,
            )
        } else {
            (
                block_number,
                user_tx_proof.public_inputs.new_user_asset_root,
            )
        };
        latest_account_tree_process_proofs.push(
            latest_account_tree
                .set(
                    user_address.0.into(),
                    GoldilocksHashOut::from_u32(last_block_number),
                )
                .unwrap(),
        );

        let proof = world_state_tree
            .set(user_address.0.into(), confirmed_user_asset_root)
            .unwrap();
        world_state_revert_proofs.push(proof);
        received_signatures.push(opt_received_signature);
    }

    let mut pw = PartialWitness::new();
    approval_block_target.set_witness(
        &mut pw,
        block_number,
        &world_state_revert_proofs,
        &user_tx_proofs
            .iter()
            .map(|p| p.public_inputs.clone())
            .collect::<Vec<_>>(),
        &received_signatures
            .iter()
            .map(|p| p.clone().map(ProofWithPublicInputs::from))
            .collect::<Vec<_>>(),
        &ProofWithPublicInputs::from(default_simple_signature),
        &latest_account_tree_process_proofs,
    );

    println!("start proving: block_proof");
    let start = Instant::now();
    let proof = circuit_data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match circuit_data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
