use std::time::Instant;

use plonky2::{
    field::types::{Field, Field64},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
    },
};

use intmax_zkp_core::{
    merkle_tree::tree::{get_merkle_proof, MerkleProof},
    rollup::{
        circuits::make_block_proof_circuit,
        gadgets::{batch::BatchBlockProofTarget, deposit_block::DepositInfo},
    },
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
    zkdsa::{
        account::{private_key_to_account, Address},
        circuits::make_simple_signature_circuit,
    },
};

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const N_LOG_MAX_BLOCKS: usize = 32;
    const N_LOG_MAX_USERS: usize = 3;
    const N_LOG_MAX_TXS: usize = 3;
    const N_LOG_MAX_CONTRACTS: usize = 3;
    const N_LOG_MAX_VARIABLES: usize = 3;
    const N_LOG_TXS: usize = 2;
    const N_LOG_RECIPIENTS: usize = 3;
    const N_LOG_CONTRACTS: usize = 3;
    const N_LOG_VARIABLES: usize = 3;
    const N_DEPOSITS: usize = 2;
    const N_DIFFS: usize = 2;
    const N_MERGES: usize = 2;
    const N_TXS: usize = 2usize.pow(N_LOG_TXS as u32);
    const N_BLOCKS: usize = 2;

    let aggregator_nodes_db = NodeDataMemory::default();
    let mut world_state_tree =
        PoseidonSparseMerkleTree::new(aggregator_nodes_db.clone(), RootDataTmp::default());

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

    // let sender2_private_key: HashOut<F> = HashOut::rand();
    // dbg!(sender2_private_key);
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

    let mut block0_deposit_tree = LayeredLayeredPoseidonSparseMerkleTree::new(
        aggregator_nodes_db.clone(),
        RootDataTmp::default(),
    );

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

    let merge_inclusion_proof1 = get_merkle_proof(&[deposit_tx_hash], 0, N_LOG_TXS);

    let default_hash = HashOut::ZERO;
    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    let default_merkle_root = get_merkle_proof(&[], 0, N_LOG_TXS).root;
    let prev_prev_block_number = 1u32;
    let mut block_headers: Vec<WrappedHashOut<F>> =
        vec![WrappedHashOut::ZERO; prev_prev_block_number as usize];
    let prev_prev_block_headers_digest = get_merkle_proof(
        &block_headers,
        prev_prev_block_number as usize - 1,
        N_LOG_MAX_BLOCKS,
    )
    .root;

    let prev_latest_account_digest = WrappedHashOut::default();
    let prev_prev_block_header = BlockHeader {
        block_number: prev_prev_block_number,
        block_headers_digest: *prev_prev_block_headers_digest,
        transactions_digest: *default_merkle_root,
        deposit_digest: *merge_inclusion_proof1.root,
        proposed_world_state_digest: default_hash,
        approved_world_state_digest: default_hash,
        latest_account_digest: *prev_latest_account_digest,
    };

    let prev_prev_block_hash = get_block_hash(&prev_prev_block_header);
    block_headers.push(prev_prev_block_hash.into());

    // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    let deposit_merge_key = PoseidonHash::two_to_one(*deposit_tx_hash, prev_prev_block_hash).into();

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

    world_state_tree
        .set(
            sender2_address.into(),
            sender2_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();
    let prev_world_state_digest = world_state_tree.get_root().unwrap();

    let prev_block_number = prev_prev_block_header.block_number + 1;
    let prev_block_headers_digest = get_merkle_proof(
        &block_headers,
        prev_block_number as usize - 1,
        N_LOG_MAX_BLOCKS,
    )
    .root;

    let prev_block_header = BlockHeader {
        block_number: prev_block_number,
        block_headers_digest: *prev_block_headers_digest,
        transactions_digest: *default_merkle_root,
        deposit_digest: default_hash,
        proposed_world_state_digest: *prev_world_state_digest,
        approved_world_state_digest: *prev_world_state_digest,
        latest_account_digest: *prev_latest_account_digest,
    };

    let prev_block_hash = get_block_hash(&prev_block_header); // `prev_block_number` 番目の block header
    block_headers.push(prev_block_hash.into());

    let merge_proof = MergeProof {
        is_deposit: true,
        diff_tree_inclusion_proof: (
            prev_prev_block_header,
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

    let mut pw = PartialWitness::new();
    merge_and_purge_circuit.targets.set_witness(
        &mut pw,
        Default::default(),
        &[],
        &[],
        &[],
        Default::default(),
        Default::default(),
    );

    println!("start proving: default_user_tx_proof");
    let start = Instant::now();
    let default_user_tx_proofs = merge_and_purge_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

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

    let proposal_world_state_root = world_state_tree.get_root();

    let zkdsa_circuit = make_simple_signature_circuit();

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
        *proposal_world_state_root.unwrap(),
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

    let block_circuit = make_block_proof_circuit::<
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
        N_TXS,
        N_DEPOSITS,
    >(&merge_and_purge_circuit, &zkdsa_circuit);

    let block_number = prev_block_header.block_number + 1;

    let accounts_in_block: Vec<(Option<_>, _)> = vec![
        (None, sender1_tx_proof),
        (Some(sender2_received_signature), sender2_tx_proof),
    ];

    let mut latest_account_tree = PoseidonSparseMerkleTree::new(
        NodeDataMemory::default(),
        RootDataTmp::from(prev_latest_account_digest),
    );

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

    let prev_block_number = prev_block_header.block_number;
    let MerkleProof {
        root: _block_headers_digest,
        siblings: block_header_siblings,
        ..
    } = get_merkle_proof(&block_headers, prev_block_number as usize, N_LOG_MAX_BLOCKS);

    let block1_deposit_list: Vec<DepositInfo<F>> = vec![DepositInfo {
        receiver_address: Address(sender2_address),
        contract_address: Address(*GoldilocksHashOut::from_u128(1)),
        variable_index: 0u8.into(),
        amount: F::from_noncanonical_u64(1),
    }];

    let mut block1_deposit_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(aggregator_nodes_db, RootDataTmp::default());
    let deposit_process_proofs = block1_deposit_list
        .iter()
        .map(|leaf| {
            block1_deposit_tree
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
    block_circuit.targets.set_witness(
        &mut pw,
        block_number,
        &user_tx_proofs,
        &default_user_tx_proofs,
        &deposit_process_proofs,
        &world_state_process_proofs,
        &world_state_revert_proofs,
        &received_signatures,
        &default_simple_signature,
        &latest_account_tree_process_proofs,
        &block_header_siblings,
        prev_block_header,
    );

    println!("start proving: block_proof");
    let start = Instant::now();
    let block_proof = block_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match block_circuit.verify(block_proof.clone()) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let block_proof_targets: BatchBlockProofTarget<D, N_BLOCKS> =
        BatchBlockProofTarget::add_virtual_to::<F, C>(&mut builder, &block_circuit.data);
    let batch_block_circuit_data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    block_proof_targets.set_witness(&mut pw, &[block_proof.into()]);

    println!("start proving: batch_block_proof");
    let start = Instant::now();
    let batch_block_proof = batch_block_circuit_data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match batch_block_circuit_data.verify(batch_block_proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
