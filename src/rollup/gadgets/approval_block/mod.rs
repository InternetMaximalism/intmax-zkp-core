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
    sparse_merkle_tree::{
        gadgets::{
            common::{conditionally_select, enforce_equal_if_enabled},
            process::process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
        },
        goldilocks_poseidon::WrappedHashOut,
    },
    transaction::circuits::{
        MergeAndPurgeTransitionPublicInputs, MergeAndPurgeTransitionPublicInputsTarget,
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
        current_block_number: u32,
        world_state_revert_proofs: &[SmtProcessProof<F>],
        user_transactions: &[MergeAndPurgeTransitionPublicInputs<F>],
        received_signatures: &[Option<SimpleSignaturePublicInputs<F>>],
        latest_account_tree_process_proofs: &[SmtProcessProof<F>],
        old_world_state_root: WrappedHashOut<F>,
        old_latest_account_root: WrappedHashOut<F>,
    ) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
        // assert!(!user_transactions.is_empty());

        pw.set_hash_target(self.old_world_state_root, *old_world_state_root);
        pw.set_hash_target(self.old_latest_account_root, *old_latest_account_root);

        let mut prev_world_state_root = old_world_state_root;
        let mut prev_latest_account_root = old_latest_account_root;
        for (world_state_revert_proof, latest_account_process_proof) in world_state_revert_proofs
            .iter()
            .zip(latest_account_tree_process_proofs.iter())
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

        for (((w, u), r), a) in world_state_revert_proofs
            .iter()
            .zip(user_transactions)
            .zip(received_signatures)
            .zip(latest_account_tree_process_proofs)
        {
            // proposed block では, user asset root は `u.new_user_asset_root` と同じであった.
            assert_eq!(w.old_value, u.new_user_asset_root);

            // merge までは signature がなくても実行されるが, purge は signature がない時には実行されない.
            let expected_new_last_block_number = if let Some(signature) = r {
                // signature が特定のメッセージに署名している時のみ有効である.
                assert_eq!(signature.message, *old_world_state_root);
                // signature が提出された時, user asset root は変わらない.
                assert_eq!(w.new_value, u.new_user_asset_root);

                WrappedHashOut::from_u32(current_block_number)
            } else {
                // signature がない時は, user asset root が merge 直後の状態 `u.middle_user_asset_root` に更新される
                assert_eq!(w.new_value, u.middle_user_asset_root);

                a.old_value
            };

            assert_eq!(a.new_value, expected_new_last_block_number);
        }

        pw.set_target(
            self.current_block_number,
            F::from_canonical_u32(current_block_number),
        );
        for (t, w) in self
            .world_state_revert_transitions
            .iter()
            .zip(world_state_revert_proofs.iter())
        {
            t.world_state_revert_proof.set_witness(pw, w);
        }

        let default_proof = SmtProcessProof::with_root(new_world_state_root);
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(world_state_revert_proofs.len())
        {
            t.world_state_revert_proof.set_witness(pw, &default_proof);
        }

        for (t, u) in self
            .world_state_revert_transitions
            .iter()
            .zip(user_transactions.iter())
        {
            t.user_transaction.set_witness(pw, u);
        }
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(user_transactions.len())
        {
            t.user_transaction.set_witness(pw, &Default::default());
        }

        for (t, r) in self
            .world_state_revert_transitions
            .iter()
            .zip(received_signatures.iter())
        {
            let r: Option<&_> = r.into();
            t.received_signature
                .0
                .set_witness(pw, r.unwrap_or(&Default::default()));
            pw.set_bool_target(t.received_signature.1, r.is_some());
        }
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(received_signatures.len())
        {
            t.received_signature.0.set_witness(pw, &Default::default());
            pw.set_bool_target(t.received_signature.1, false);
        }

        for t in self
            .world_state_revert_transitions
            .iter()
            .take(user_transactions.len())
        {
            pw.set_bool_target(t.enabled, true);
        }

        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(user_transactions.len())
        {
            pw.set_bool_target(t.enabled, false);
        }

        for (t, a) in self
            .world_state_revert_transitions
            .iter()
            .zip(latest_account_tree_process_proofs.iter())
        {
            t.latest_account_process_proof.set_witness(pw, a);
        }

        let default_proof = SmtProcessProof::with_root(new_latest_account_root);
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(latest_account_tree_process_proofs.len())
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

        // 特定のメッセージに署名したことを確かめる.
        enforce_equal_if_enabled(
            builder,
            signature.message,
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

#[test]
fn test_approval_block() {
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
        config::RollupConstants,
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
            circuits::make_user_proof_circuit,
            gadgets::merge::MergeProof,
            tree::user_asset::UserAssetTree,
        },
        zkdsa::{account::private_key_to_account, circuits::make_simple_signature_circuit},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const ROLLUP_CONSTANTS: RollupConstants = RollupConstants {
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
    let n_txs = 1 << ROLLUP_CONSTANTS.log_n_txs;

    let aggregator_nodes_db = NodeDataMemory::default();
    let mut world_state_tree =
        PoseidonSparseMerkleTree::new(aggregator_nodes_db.clone(), RootDataTmp::default());

    let config = CircuitConfig::standard_recursion_config();
    let merge_and_purge_circuit = make_user_proof_circuit::<F, C, D>(config, ROLLUP_CONSTANTS);

    // dbg!(&purge_proof_circuit_data.common);

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

    let mut block0_deposit_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(aggregator_nodes_db, RootDataTmp::default());

    block0_deposit_tree
        .set(sender2_address.into(), key1.1, key1.2, value1)
        .unwrap();
    block0_deposit_tree
        .set(sender2_address.into(), key2.1, key2.2, value2)
        .unwrap();

    let block0_deposit_tree: PoseidonSparseMerkleTree<_, _> = block0_deposit_tree.into();

    let merge_inclusion_proof2 = block0_deposit_tree.find(&sender2_address.into()).unwrap();

    // `merge_inclusion_proof2` の root を `diff_root`, `hash(diff_root, nonce)` の値を `tx_hash` とよぶ.
    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root = merge_inclusion_proof2.root;
    let deposit_tx_hash = PoseidonHash::two_to_one(*deposit_diff_root, deposit_nonce).into();

    let merge_inclusion_proof1 =
        get_merkle_proof(&[deposit_tx_hash], 0, ROLLUP_CONSTANTS.log_n_txs);

    let default_hash = HashOut::ZERO;
    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    // let default_merkle_root = get_merkle_proof(&[], 0, LOG_N_TXS).root;
    let mut prev_block_header = BlockHeader::new(ROLLUP_CONSTANTS.log_n_txs);
    prev_block_header.block_number = 1;
    prev_block_header.deposit_digest = *merge_inclusion_proof1.root;
    // let prev_block_header = BlockHeader {
    //     block_number: 1,
    //     prev_block_hash: default_hash,
    //     block_headers_digest: default_hash,
    //     transactions_digest: *default_merkle_root,
    //     deposit_digest: *merge_inclusion_proof1.root,
    //     proposed_world_state_digest: default_hash,
    //     approved_world_state_digest: default_hash,
    //     latest_account_digest: default_hash,
    // };

    let block_hash = get_block_hash(&prev_block_header);

    // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    let deposit_merge_key = PoseidonHash::two_to_one(*deposit_tx_hash, block_hash).into();

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
            prev_block_header.clone(),
            merge_inclusion_proof1,
            merge_inclusion_proof2,
        ),
        merge_process_proof,
        latest_account_tree_inclusion_proof: default_inclusion_proof,
        nonce: deposit_nonce.into(),
    };

    world_state_tree
        .set(
            sender2_address.into(),
            sender2_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();

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

    let sender1_nonce = WrappedHashOut::from(HashOut {
        elements: [
            F::from_canonical_u64(7823975322825286183),
            F::from_canonical_u64(9539665429968124165),
            F::from_canonical_u64(6825628074508059665),
            F::from_canonical_u64(17852854585777218254),
        ],
    });

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

    let sender2_nonce = WrappedHashOut::from(HashOut {
        elements: [
            F::from_canonical_u64(6657881311364026367),
            F::from_canonical_u64(11761473381903976612),
            F::from_canonical_u64(10768494808833234712),
            F::from_canonical_u64(3223267375194257474),
        ],
    });

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

    world_state_process_proofs.push(sender1_world_state_process_proof);
    user_tx_proofs.push(sender1_tx_proof.clone());
    world_state_process_proofs.push(sender2_world_state_process_proof);
    user_tx_proofs.push(sender2_tx_proof.clone());

    let config = CircuitConfig::standard_recursion_config();
    let zkdsa_circuit = make_simple_signature_circuit::<F, C, D>(config);

    // let mut pw = PartialWitness::new();
    // zkdsa_circuit.targets.set_witness(
    //     &mut pw,
    //     sender1_account.private_key,
    //     *world_state_tree.get_root().unwrap(),
    // );

    // println!("start proving: sender1_received_signature");
    // let start = Instant::now();
    // let sender1_received_signature = zkdsa_circuit.prove(pw).unwrap();
    // let end = start.elapsed();
    // println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender1_received_signature.public_inputs);

    let mut pw = PartialWitness::new();
    zkdsa_circuit.targets.set_witness(
        &mut pw,
        sender2_account.private_key,
        *world_state_tree.get_root().unwrap(),
    );

    println!("start proving: sender2_received_signature");
    let start = Instant::now();
    let sender2_received_signature = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender2_received_signature.public_inputs);

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let approval_block_target = ApprovalBlockProductionTarget::add_virtual_to::<
        F,
        <C as GenericConfig<D>>::Hasher,
        D,
    >(&mut builder, ROLLUP_CONSTANTS.log_max_n_users, n_txs);
    let circuit_data = builder.build::<C>();

    let block_number = prev_block_header.block_number + 1;

    let accounts_in_block: Vec<(Option<_>, _)> = vec![
        (None, sender1_tx_proof),
        (Some(sender2_received_signature), sender2_tx_proof),
    ];

    let mut latest_account_tree =
        PoseidonSparseMerkleTree::new(NodeDataMemory::default(), RootDataTmp::default());

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
                user_tx_proof.public_inputs.middle_user_asset_root,
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
    approval_block_target.set_witness::<F, D>(
        &mut pw,
        block_number,
        &world_state_revert_proofs,
        &user_tx_proofs
            .iter()
            .map(|p| p.public_inputs.clone())
            .collect::<Vec<_>>(),
        &received_signatures
            .iter()
            .cloned()
            .map(|p| p.map(|p| p.public_inputs))
            .collect::<Vec<_>>(),
        &latest_account_tree_process_proofs,
        world_state_revert_proofs.first().unwrap().old_root,
        latest_account_tree_process_proofs.first().unwrap().old_root,
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
