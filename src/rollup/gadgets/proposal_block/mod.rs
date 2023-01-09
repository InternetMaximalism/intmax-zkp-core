use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    merkle_tree::{
        gadgets::get_merkle_root_target_from_leaves,
        tree::{get_merkle_proof_with_zero, log2_ceil},
    },
    sparse_merkle_tree::{
        gadgets::{
            common::logical_or,
            process::{
                process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
                utils::{
                    get_process_merkle_proof_role, verify_layered_smt_target_connection,
                    ProcessMerkleProofRoleTarget,
                },
            },
        },
        goldilocks_poseidon::WrappedHashOut,
        layered_tree::verify_layered_smt_connection,
        proof::ProcessMerkleProofRole,
    },
    transaction::circuits::{
        MergeAndPurgeTransitionPublicInputs, MergeAndPurgeTransitionPublicInputsTarget,
    },
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
    ) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
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
                u.old_user_asset_root,
                u.new_user_asset_root,
            )
            .unwrap();
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
            transaction_hashes.push(u.tx_hash);
        }

        let default_tx_hash = MergeAndPurgeTransitionPublicInputs::default().tx_hash;

        let log_n_txs = log2_ceil(n_txs);
        assert_eq!(2usize.pow(log_n_txs), n_txs);
        let transactions_digest =
            get_merkle_proof_with_zero(&transaction_hashes, 0, log_n_txs as usize, default_tx_hash)
                .root;

        (transactions_digest, new_world_state_root)
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

#[test]
fn test_proposal_block() {
    use std::time::Instant;

    use plonky2::{
        field::types::Field,
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
                PoseidonSparseMerkleTree, RootDataTmp, WrappedHashOut,
            },
            proof::SparseMerkleInclusionProof,
        },
        transaction::{
            block_header::{get_block_hash, BlockHeader},
            gadgets::merge::MergeProof,
            tree::user_asset::UserAssetTree,
        },
        zkdsa::account::{private_key_to_account, Address},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const LOG_MAX_N_BLOCKS: usize = 32;
    const LOG_MAX_N_USERS: usize = 3;
    const LOG_N_TXS: usize = 2;
    const N_TXS: usize = 2usize.pow(LOG_N_TXS as u32);

    let aggregator_nodes_db = NodeDataMemory::default();
    let mut world_state_tree =
        PoseidonSparseMerkleTree::new(aggregator_nodes_db.clone(), RootDataTmp::default());

    let sender1_private_key = HashOut {
        elements: [
            F::from_canonical_u64(17426287337377512978),
            F::from_canonical_u64(8703645504073070742),
            F::from_canonical_u64(11984317793392655464),
            F::from_canonical_u64(9979414176933652180),
        ],
    };
    let sender1_account = private_key_to_account(sender1_private_key);
    let sender1_address = sender1_account.address.0;

    let sender1_nodes_db = NodeDataMemory::default();
    let mut sender1_user_asset_tree =
        UserAssetTree::new(sender1_nodes_db.clone(), RootDataTmp::default());

    let mut sender1_tx_diff_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(sender1_nodes_db, RootDataTmp::default());

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
            sender1_user_asset_tree.get_root().unwrap(),
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
            F::from_canonical_u64(15657143458229430356),
            F::from_canonical_u64(6012455030006979790),
            F::from_canonical_u64(4280058849535143691),
            F::from_canonical_u64(5153662694263190591),
        ],
    };
    let sender2_account = private_key_to_account(sender2_private_key);
    let sender2_address = sender2_account.address.0;

    let sender2_nodes_db = NodeDataMemory::default();
    let mut sender2_user_asset_tree =
        UserAssetTree::new(sender2_nodes_db.clone(), RootDataTmp::default());

    let mut sender2_tx_diff_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(sender2_nodes_db, RootDataTmp::default());

    let mut block1_deposit_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(aggregator_nodes_db, RootDataTmp::default());

    block1_deposit_tree
        .set(sender2_address.into(), key1.1, key1.2, value1)
        .unwrap();
    block1_deposit_tree
        .set(sender2_address.into(), key2.1, key2.2, value2)
        .unwrap();

    let block1_deposit_tree: PoseidonSparseMerkleTree<_, _> = block1_deposit_tree.into();

    let merge_inclusion_proof2 = block1_deposit_tree.find(&sender2_address.into()).unwrap();

    // `merge_inclusion_proof2` の root を `diff_root`, `hash(diff_root, nonce)` の値を `tx_hash` とよぶ.
    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root = merge_inclusion_proof2.root;
    let deposit_tx_hash = PoseidonHash::two_to_one(*deposit_diff_root, deposit_nonce).into();

    let merge_inclusion_proof1 = get_merkle_proof(&[deposit_tx_hash], 0, LOG_N_TXS);

    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    let default_tx_hash = MergeAndPurgeTransitionPublicInputs::default().tx_hash;
    let default_transactions_digest =
        get_merkle_proof_with_zero(&[], 0, LOG_N_TXS, default_tx_hash).root;
    let prev_block_number = 1u32;
    let mut block_headers: Vec<WrappedHashOut<F>> =
        vec![WrappedHashOut::ZERO; prev_block_number as usize];
    let prev_block_headers_digest = get_merkle_proof(
        &block_headers,
        prev_block_number as usize - 1,
        LOG_MAX_N_BLOCKS,
    )
    .root;

    let prev_world_state_digest = world_state_tree.get_root().unwrap();
    let prev_latest_account_digest = WrappedHashOut::default();
    let prev_block_header = BlockHeader {
        block_number: prev_block_number,
        prev_block_hash: Default::default(),
        block_headers_digest: *prev_block_headers_digest,
        transactions_digest: *default_transactions_digest,
        deposit_digest: *merge_inclusion_proof1.root,
        proposed_world_state_digest: *prev_world_state_digest,
        approved_world_state_digest: *prev_world_state_digest,
        latest_account_digest: *prev_latest_account_digest,
    };

    let prev_block_hash = get_block_hash(&prev_block_header);
    block_headers.push(prev_block_hash.into());

    // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    let deposit_merge_key = PoseidonHash::two_to_one(*deposit_tx_hash, prev_block_hash).into();

    // user_asset_tree に deposit を merge する.
    sender2_user_asset_tree
        .set(deposit_merge_key, key1.1, key1.2, value1)
        .unwrap();
    sender2_user_asset_tree
        .set(deposit_merge_key, key2.1, key2.2, value2)
        .unwrap();

    let mut sender2_user_asset_tree: PoseidonSparseMerkleTree<_, _> =
        sender2_user_asset_tree.into();
    let asset_root = sender2_user_asset_tree.get(&deposit_merge_key).unwrap();
    sender2_user_asset_tree
        .set(deposit_merge_key, Default::default())
        .unwrap();
    let merge_process_proof = sender2_user_asset_tree
        .set(deposit_merge_key, asset_root)
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

    let mut sender2_user_asset_tree: UserAssetTree<_, _> = sender2_user_asset_tree.into();
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

    // let sender1_nonce: WrappedHashOut<F> = WrappedHashOut::rand();
    // dbg!(sender1_nonce);
    let sender1_nonce = WrappedHashOut::from(HashOut {
        elements: [
            F::from_canonical_u64(7823975322825286183),
            F::from_canonical_u64(9539665429968124165),
            F::from_canonical_u64(6825628074508059665),
            F::from_canonical_u64(17852854585777218254),
        ],
    });

    let sender1_transaction = {
        let old_user_asset_root = sender1_input_witness.first().unwrap().0.old_root;
        let middle_user_asset_root = old_user_asset_root;
        let new_user_asset_root = sender1_input_witness.last().unwrap().0.new_root;
        let diff_root = sender1_output_witness.last().unwrap().0.new_root;
        let tx_hash = PoseidonHash::two_to_one(*diff_root, *sender1_nonce);

        MergeAndPurgeTransitionPublicInputs {
            sender_address: Address(sender1_address),
            old_user_asset_root,
            middle_user_asset_root,
            new_user_asset_root,
            diff_root,
            tx_hash: tx_hash.into(),
        }
    };

    let sender2_nonce = WrappedHashOut::from(HashOut {
        elements: [
            F::from_canonical_u64(6657881311364026367),
            F::from_canonical_u64(11761473381903976612),
            F::from_canonical_u64(10768494808833234712),
            F::from_canonical_u64(3223267375194257474),
        ],
    });

    let sender2_transaction = {
        let old_user_asset_root = merge_proof.merge_process_proof.old_root;
        let middle_user_asset_root = sender2_input_witness.first().unwrap().0.old_root;
        let new_user_asset_root = sender2_input_witness.last().unwrap().0.new_root;
        let diff_root = sender2_output_witness.last().unwrap().0.new_root;
        let tx_hash = PoseidonHash::two_to_one(*diff_root, *sender2_nonce);

        MergeAndPurgeTransitionPublicInputs {
            sender_address: Address(sender2_address),
            old_user_asset_root,
            middle_user_asset_root,
            new_user_asset_root,
            diff_root,
            tx_hash: tx_hash.into(),
        }
    };

    let mut world_state_process_proofs = vec![];
    let mut user_transactions = vec![];

    let sender1_world_state_process_proof = world_state_tree
        .set(
            sender1_address.into(),
            sender1_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();

    // dbg!(serde_json::to_string(&sender1_world_state_process_proof).unwrap());

    let sender2_world_state_process_proof = world_state_tree
        .set(
            sender2_address.into(),
            sender2_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();
    // dbg!(&sender2_world_state_process_proof);

    world_state_process_proofs.push(sender1_world_state_process_proof);
    user_transactions.push(sender1_transaction);
    world_state_process_proofs.push(sender2_world_state_process_proof);
    user_transactions.push(sender2_transaction);

    // proposal block
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proposal_block_target = ProposalBlockProductionTarget::add_virtual_to::<
        F,
        <C as GenericConfig<D>>::Hasher,
        D,
    >(&mut builder, LOG_MAX_N_USERS, N_TXS);
    builder.register_public_inputs(&proposal_block_target.transactions_digest.elements);
    builder.register_public_inputs(&proposal_block_target.new_world_state_root.elements);
    let circuit_data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    let (transactions_digest, new_world_state_root) = proposal_block_target.set_witness::<F, D>(
        &mut pw,
        &world_state_process_proofs,
        &user_transactions,
        world_state_process_proofs.first().unwrap().old_root,
        // prev_block_header.approved_world_state_digest.into(),
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
