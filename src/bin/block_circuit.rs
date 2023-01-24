use std::time::Instant;

use intmax_zkp_core::{
    config::RollupConstants,
    rollup::{
        block::make_sample_circuit_inputs,
        circuits::{make_block_proof_circuit, BlockDetail},
        gadgets::{batch::BlockBatchTarget, deposit_block::DepositBlockProduction},
    },
    transaction::circuits::{make_user_proof_circuit, MergeAndPurgeTransition},
    zkdsa::circuits::make_simple_signature_circuit,
};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    // const LOG_MAX_N_BLOCKS: usize = 32;
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

    let examples = make_sample_circuit_inputs::<C, D>(rollup_constants);

    // let aggregator_nodes_db = NodeDataMemory::default();
    // let mut world_state_tree =
    //     PoseidonSparseMerkleTree::new(aggregator_nodes_db.clone(), RootDataTmp::default());

    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let merge_and_purge_circuit = make_user_proof_circuit::<F, C, D>(config, rollup_constants);

    // // dbg!(&purge_proof_circuit_data.common);

    // let sender1_private_key = HashOut {
    //     elements: [
    //         F::from_canonical_u64(17426287337377512978),
    //         F::from_canonical_u64(8703645504073070742),
    //         F::from_canonical_u64(11984317793392655464),
    //         F::from_canonical_u64(9979414176933652180),
    //     ],
    // };
    // let sender1_account = private_key_to_account(sender1_private_key);
    // let sender1_address = sender1_account.address.0;

    // let sender1_nodes_db = NodeDataMemory::default();
    // let mut sender1_user_asset_tree =
    //     UserAssetTree::new(sender1_nodes_db.clone(), RootDataTmp::default());

    // let mut sender1_tx_diff_tree =
    //     LayeredLayeredPoseidonSparseMerkleTree::new(sender1_nodes_db, RootDataTmp::default());

    // let key1 = (
    //     GoldilocksHashOut::from_u128(12),
    //     GoldilocksHashOut::from_u128(305),
    //     GoldilocksHashOut::from_u128(8012),
    // );
    // let value1 = GoldilocksHashOut::from_u128(2053);
    // let key2 = (
    //     GoldilocksHashOut::from_u128(12),
    //     GoldilocksHashOut::from_u128(471),
    //     GoldilocksHashOut::from_u128(8012),
    // );
    // let value2 = GoldilocksHashOut::from_u128(1111);

    // let key3 = (
    //     GoldilocksHashOut::from_u128(407),
    //     GoldilocksHashOut::from_u128(305),
    //     GoldilocksHashOut::from_u128(8012),
    // );
    // let value3 = GoldilocksHashOut::from_u128(2053);
    // let key4 = (
    //     GoldilocksHashOut::from_u128(832),
    //     GoldilocksHashOut::from_u128(471),
    //     GoldilocksHashOut::from_u128(8012),
    // );
    // let value4 = GoldilocksHashOut::from_u128(1111);

    // let zero = GoldilocksHashOut::from_u128(0);
    // sender1_user_asset_tree
    //     .set(key1.0, key1.1, key1.2, value1)
    //     .unwrap();
    // sender1_user_asset_tree
    //     .set(key2.0, key2.1, key2.2, value2)
    //     .unwrap();

    // world_state_tree
    //     .set(
    //         sender1_account.address.0.into(),
    //         sender1_user_asset_tree.get_root().unwrap(),
    //     )
    //     .unwrap();

    // let proof1 = sender1_user_asset_tree
    //     .set(key2.0, key2.1, key2.2, zero)
    //     .unwrap();
    // let proof2 = sender1_user_asset_tree
    //     .set(key1.0, key1.1, key1.2, zero)
    //     .unwrap();

    // let proof3 = sender1_tx_diff_tree
    //     .set(key3.0, key3.1, key3.2, value3)
    //     .unwrap();
    // let proof4 = sender1_tx_diff_tree
    //     .set(key4.0, key4.1, key4.2, value4)
    //     .unwrap();

    // let sender1_input_witness = vec![proof1, proof2];
    // let sender1_output_witness = vec![proof3, proof4];

    // let sender2_private_key = HashOut {
    //     elements: [
    //         F::from_canonical_u64(15657143458229430356),
    //         F::from_canonical_u64(6012455030006979790),
    //         F::from_canonical_u64(4280058849535143691),
    //         F::from_canonical_u64(5153662694263190591),
    //     ],
    // };
    // let sender2_account = private_key_to_account(sender2_private_key);
    // let sender2_address = sender2_account.address.0;

    // let sender2_nodes_db = NodeDataMemory::default();
    // let mut sender2_user_asset_tree =
    //     UserAssetTree::new(sender2_nodes_db.clone(), RootDataTmp::default());

    // let mut sender2_tx_diff_tree =
    //     LayeredLayeredPoseidonSparseMerkleTree::new(sender2_nodes_db, RootDataTmp::default());

    // let mut block1_deposit_tree = LayeredLayeredPoseidonSparseMerkleTree::new(
    //     aggregator_nodes_db.clone(),
    //     RootDataTmp::default(),
    // );

    // block1_deposit_tree
    //     .set(sender2_address.into(), key1.1, key1.2, value1)
    //     .unwrap();
    // block1_deposit_tree
    //     .set(sender2_address.into(), key2.1, key2.2, value2)
    //     .unwrap();

    // let block1_deposit_tree: PoseidonSparseMerkleTree<_, _> = block1_deposit_tree.into();

    // let merge_inclusion_proof2 = block1_deposit_tree.find(&sender2_address.into()).unwrap();

    // // `merge_inclusion_proof2` の root を `diff_root`, `hash(diff_root, nonce)` の値を `tx_hash` とよぶ.
    // let deposit_nonce = HashOut::ZERO;
    // let deposit_diff_root = merge_inclusion_proof2.root;
    // let deposit_tx_hash = PoseidonHash::two_to_one(*deposit_diff_root, deposit_nonce).into();

    // let merge_inclusion_proof1 =
    //     get_merkle_proof(&[deposit_tx_hash], 0, ROLLUP_CONSTANTS.log_n_txs);

    // let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    // let default_merkle_root = get_merkle_proof(&[], 0, ROLLUP_CONSTANTS.log_n_txs).root;
    // let prev_block_number = 1u32;
    // let mut block_headers: Vec<WrappedHashOut<F>> =
    //     vec![WrappedHashOut::ZERO; prev_block_number as usize];
    // let prev_block_headers_digest = get_merkle_proof(
    //     &block_headers,
    //     prev_block_number as usize - 1,
    //     LOG_MAX_N_BLOCKS,
    // )
    // .root;

    // let prev_world_state_digest = world_state_tree.get_root().unwrap();
    // let prev_latest_account_digest = WrappedHashOut::default();
    // let prev_block_header = BlockHeader {
    //     block_number: prev_block_number,
    //     prev_block_hash: Default::default(),
    //     block_headers_digest: *prev_block_headers_digest,
    //     transactions_digest: *default_merkle_root,
    //     deposit_digest: *merge_inclusion_proof1.root,
    //     proposed_world_state_digest: *prev_world_state_digest,
    //     approved_world_state_digest: *prev_world_state_digest,
    //     latest_account_digest: *prev_latest_account_digest,
    // };

    // let prev_block_hash = get_block_hash(&prev_block_header);
    // block_headers.push(prev_block_hash.into());

    // // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    // let deposit_merge_key = PoseidonHash::two_to_one(*deposit_tx_hash, prev_block_hash).into();

    // // user_asset_tree に deposit を merge する.
    // sender2_user_asset_tree
    //     .set(deposit_merge_key, key1.1, key1.2, value1)
    //     .unwrap();
    // sender2_user_asset_tree
    //     .set(deposit_merge_key, key2.1, key2.2, value2)
    //     .unwrap();

    // let mut sender2_user_asset_tree: PoseidonSparseMerkleTree<_, _> =
    //     sender2_user_asset_tree.into();
    // let asset_root = sender2_user_asset_tree.get(&deposit_merge_key).unwrap();
    // sender2_user_asset_tree
    //     .set(deposit_merge_key, Default::default())
    //     .unwrap();
    // let merge_process_proof = sender2_user_asset_tree
    //     .set(deposit_merge_key, asset_root)
    //     .unwrap();

    // let merge_proof = MergeProof {
    //     is_deposit: true,
    //     diff_tree_inclusion_proof: (
    //         prev_block_header.clone(),
    //         merge_inclusion_proof1,
    //         merge_inclusion_proof2,
    //     ),
    //     merge_process_proof,
    //     latest_account_tree_inclusion_proof: default_inclusion_proof,
    //     nonce: deposit_nonce.into(),
    // };

    // let mut sender2_user_asset_tree: UserAssetTree<_, _> = sender2_user_asset_tree.into();
    // let proof1 = sender2_user_asset_tree
    //     .set(deposit_merge_key, key2.1, key2.2, zero)
    //     .unwrap();
    // let proof2 = sender2_user_asset_tree
    //     .set(deposit_merge_key, key1.1, key1.2, zero)
    //     .unwrap();

    // let proof3 = sender2_tx_diff_tree
    //     .set(key3.0, key3.1, key3.2, value3)
    //     .unwrap();
    // let proof4 = sender2_tx_diff_tree
    //     .set(key4.0, key4.1, key4.2, value4)
    //     .unwrap();

    // let sender2_input_witness = vec![proof1, proof2];
    // let sender2_output_witness = vec![proof3, proof4];
    // // dbg!(
    // //     serde_json::to_string(&sender2_input_witness).unwrap(),
    // //     serde_json::to_string(&sender2_output_witness).unwrap()
    // // );

    // let sender1_nonce = WrappedHashOut::from(HashOut {
    //     elements: [
    //         F::from_canonical_u64(7823975322825286183),
    //         F::from_canonical_u64(9539665429968124165),
    //         F::from_canonical_u64(6825628074508059665),
    //         F::from_canonical_u64(17852854585777218254),
    //     ],
    // });

    let mut pw = PartialWitness::new();
    merge_and_purge_circuit
        .targets
        .set_witness(&mut pw, &examples[0].transactions[0].0);

    println!("start proving: sender1_tx_proof");
    let start = Instant::now();
    let sender1_tx_proof = merge_and_purge_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    merge_and_purge_circuit
        .verify(sender1_tx_proof.clone())
        .unwrap();

    // let sender2_nonce = WrappedHashOut::from(HashOut {
    //     elements: [
    //         F::from_canonical_u64(6657881311364026367),
    //         F::from_canonical_u64(11761473381903976612),
    //         F::from_canonical_u64(10768494808833234712),
    //         F::from_canonical_u64(3223267375194257474),
    //     ],
    // });

    let mut pw = PartialWitness::new();
    merge_and_purge_circuit
        .targets
        .set_witness(&mut pw, &examples[0].transactions[1].0);

    println!("start proving: sender2_tx_proof");
    let start = Instant::now();
    let sender2_tx_proof = merge_and_purge_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    merge_and_purge_circuit
        .verify(sender2_tx_proof.clone())
        .unwrap();

    let mut pw = PartialWitness::new();
    merge_and_purge_circuit
        .targets
        .set_witness::<F, H>(&mut pw, &MergeAndPurgeTransition::default());

    println!("start proving: default_user_tx_proof");
    let start = Instant::now();
    let default_user_tx_proof = merge_and_purge_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // let mut world_state_process_proofs = vec![];
    let user_tx_proofs = vec![sender1_tx_proof, sender2_tx_proof];

    // let sender1_world_state_process_proof = world_state_tree
    //     .set(
    //         sender1_address.into(),
    //         sender1_user_asset_tree.get_root().unwrap(),
    //     )
    //     .unwrap();

    // // dbg!(serde_json::to_string(&sender1_world_state_process_proof).unwrap());

    // let sender2_world_state_process_proof = world_state_tree
    //     .set(
    //         sender2_address.into(),
    //         sender2_user_asset_tree.get_root().unwrap(),
    //     )
    //     .unwrap();

    // world_state_process_proofs.push(sender1_world_state_process_proof);
    // world_state_process_proofs.push(sender2_world_state_process_proof);

    // let proposal_world_state_root = world_state_tree.get_root().unwrap();

    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let zkdsa_circuit = make_simple_signature_circuit(config);

    // // // let mut pw = PartialWitness::new();
    // // // zkdsa_circuit.targets.set_witness(
    // // //     &mut pw,
    // // //     sender1_account.private_key,
    // // //     *world_state_tree.get_root().unwrap(),
    // // // );

    // // // println!("start proving: sender1_received_signature");
    // // // let start = Instant::now();
    // // // let sender1_received_signature = zkdsa_circuit.prove(pw).unwrap();
    // // // let end = start.elapsed();
    // // // println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // // // dbg!(&sender1_received_signature.public_inputs);

    let mut pw = PartialWitness::new();
    zkdsa_circuit
        .targets
        .set_witness(&mut pw, examples[0].transactions[1].1.as_ref().unwrap());

    println!("start proving: sender2_received_signature");
    let start = Instant::now();
    let sender2_received_signature_proof = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&sender2_received_signature.public_inputs);

    let mut pw = PartialWitness::new();
    zkdsa_circuit
        .targets
        .set_witness(&mut pw, &Default::default());

    println!("start proving: default_simple_signature");
    let start = Instant::now();
    let default_simple_signature_proof = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    let config = CircuitConfig::standard_recursion_config();
    let block_circuit = make_block_proof_circuit::<F, C, D>(
        config,
        rollup_constants,
        &merge_and_purge_circuit,
        &zkdsa_circuit,
    );

    // let block_number = prev_block_header.block_number + 1;

    let received_signature_proofs = vec![None, Some(sender2_received_signature_proof)];
    // let received_signatures = received_signature_proofs
    //     .iter()
    //     .cloned()
    //     .map(|v| v.map(|proof| proof.public_inputs))
    //     .collect::<Vec<_>>();

    // let mut latest_account_tree = PoseidonSparseMerkleTree::new(
    //     NodeDataMemory::default(),
    //     RootDataTmp::from(prev_latest_account_digest),
    // );

    // // NOTICE: merge proof の中に deposit が混ざっていると, revert proof がうまく出せない場合がある.
    // // deposit してそれを消費して old: 0 -> middle: non-zero -> new: 0 となった場合は,
    // // u.enabled かつ w.fnc == NoOp だが revert ではない.
    // let mut world_state_revert_proofs = vec![];
    // let mut latest_account_process_proofs = vec![];
    // let user_transactions = user_tx_proofs
    //     .iter()
    //     .cloned()
    //     .map(|v| v.public_inputs)
    //     .collect::<Vec<_>>();
    // for (opt_received_signature, user_transaction) in
    //     received_signatures.iter().zip(user_transactions.iter())
    // {
    //     let user_address = user_transaction.sender_address;
    //     let (last_block_number, confirmed_user_asset_root) = if opt_received_signature.is_none() {
    //         let old_block_number = latest_account_tree.get(&user_address.0.into()).unwrap();
    //         (
    //             old_block_number.to_u32(),
    //             user_transaction.middle_user_asset_root,
    //         )
    //     } else {
    //         (block_number, user_transaction.new_user_asset_root)
    //     };
    //     latest_account_process_proofs.push(
    //         latest_account_tree
    //             .set(
    //                 user_address.0.into(),
    //                 GoldilocksHashOut::from_u32(last_block_number),
    //             )
    //             .unwrap(),
    //     );

    //     let proof = world_state_tree
    //         .set(user_address.0.into(), confirmed_user_asset_root)
    //         .unwrap();
    //     world_state_revert_proofs.push(proof);
    // }

    // let prev_block_number = prev_block_header.block_number;
    // let MerkleProof {
    //     root: block_headers_digest,
    //     siblings: block_headers_proof_siblings,
    //     ..
    // } = get_merkle_proof(&block_headers, prev_block_number as usize, LOG_MAX_N_BLOCKS);

    // let block2_deposit_list = vec![ContributedAsset {
    //     receiver_address: Address(sender2_address),
    //     kind: TokenKind {
    //         contract_address: Address(*GoldilocksHashOut::from_u128(1)),
    //         variable_index: 0u8.into(),
    //     },
    //     amount: 1,
    // }];

    // let mut block2_deposit_tree =
    //     LayeredLayeredPoseidonSparseMerkleTree::new(aggregator_nodes_db, RootDataTmp::default());
    // let deposit_process_proofs = block2_deposit_list
    //     .iter()
    //     .map(|leaf| {
    //         block2_deposit_tree
    //             .set(
    //                 leaf.receiver_address.0.into(),
    //                 leaf.contract_address.0.into(),
    //                 leaf.variable_index.to_hash_out().into(),
    //                 HashOut::from_partial(&[leaf.amount]).into(),
    //             )
    //             .unwrap()
    //     })
    //     .collect::<Vec<_>>();

    // {
    //     let deposit_list = examples[0]
    //         .deposit_process_proofs
    //         .iter()
    //         .map(|proof_t| ContributedAsset {
    //             receiver_address: Address(*proof_t.0.new_key),
    //             kind: TokenKind {
    //                 contract_address: Address(*proof_t.1.new_key),
    //                 variable_index: VariableIndex::from_hash_out(*proof_t.2.new_key),
    //             },
    //             amount: proof_t.2.new_value.elements[0],
    //         })
    //         .collect::<Vec<_>>();
    //     let interior_deposit_digest = deposit_process_proofs.last().unwrap().0.new_root;
    //     let deposit_digest =
    //         get_merkle_proof(&[interior_deposit_digest], 0, ROLLUP_CONSTANTS.log_n_txs).root;

    //     let user_transactions: Vec<MergeAndPurgeTransitionPublicInputs<F>> = vec![];
    //     let transaction_hashes = user_transactions
    //         .iter()
    //         .map(|v| v.tx_hash)
    //         .collect::<Vec<_>>();
    //     let default_tx_hash = MergeAndPurgeTransitionPublicInputs::default().tx_hash;
    //     let transactions_digest = get_merkle_proof_with_zero(
    //         &transaction_hashes,
    //         0,
    //         ROLLUP_CONSTANTS.log_n_txs,
    //         default_tx_hash,
    //     )
    //     .root;

    //     let address_list = examples[0]
    //         .transactions
    //         .iter()
    //         .map(
    //             |(user_tx_proof, received_signature_proof)| TransactionSenderWithValidity {
    //                 sender_address: user_tx_proof.sender_address,
    //                 is_valid: received_signature_proof.is_some(),
    //             },
    //         )
    //         .collect::<Vec<_>>();

    //     let block_header = BlockHeader {
    //         block_number,
    //         prev_block_hash,
    //         block_headers_digest: *block_headers_digest,
    //         transactions_digest: *transactions_digest,
    //         deposit_digest: *deposit_digest,
    //         proposed_world_state_digest: *world_state_process_proofs.last().unwrap().new_root,
    //         approved_world_state_digest: *world_state_revert_proofs.last().unwrap().new_root,
    //         latest_account_digest: *latest_account_process_proofs.last().unwrap().new_root,
    //     };

    //     let block_info = BlockInfo {
    //         header: block_header,
    //         transactions: transaction_hashes,
    //         deposit_list,
    //         address_list,
    //     };

    //     use std::io::Write;
    //     let mut f = std::fs::OpenOptions::new()
    //         .create(true)
    //         .write(true)
    //         .open("./test_cases/block1_info.json")
    //         .unwrap();
    //     write!(&mut f, "{}", serde_json::to_string(&block_info).unwrap()).unwrap();

    //     let json = std::fs::read_to_string("test_cases/block1_info.json").unwrap();
    //     let decoded_block_info: BlockInfo<F> = serde_json::from_str(&json).unwrap();

    //     assert_eq!(decoded_block_info, block_info);
    // }

    let input = BlockDetail::<F, C, D> {
        block_number: examples[0].approval_block.current_block_number,
        user_tx_proofs,
        deposit_process_proofs: DepositBlockProduction {
            deposit_process_proofs: examples[0].deposit_process_proofs.clone(),
            log_n_recipients: rollup_constants.log_n_recipients,
            log_n_kinds: rollup_constants.log_n_contracts + rollup_constants.log_max_n_variables,
        },
        world_state_process_proofs: examples[0].world_state_process_proofs.clone(),
        world_state_revert_proofs: examples[0].approval_block.world_state_revert_proofs.clone(),
        received_signature_proofs,
        latest_account_process_proofs: examples[0]
            .approval_block
            .latest_account_tree_process_proofs
            .clone(),
        block_headers_proof_siblings: examples[0].block_headers_proof_siblings.clone(),
        prev_block_header: examples[0].prev_block_header.clone(),
    };
    println!("start proving: block_proof");
    let start = Instant::now();
    let block_proof = block_circuit
        .set_witness_and_prove(
            &input,
            &default_user_tx_proof,
            &default_simple_signature_proof,
        )
        .expect("fail to set witness or generate proof");
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    block_circuit.verify(block_proof.clone()).unwrap();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let block_proof_targets: BlockBatchTarget<D> = BlockBatchTarget::add_virtual_to::<F, C>(
        &mut builder,
        &block_circuit.data,
        rollup_constants.n_blocks,
    );
    let batch_block_circuit_data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    block_proof_targets.set_witness(&mut pw, &[block_proof.into()]);

    println!("start proving: batch_block_proof");
    let start = Instant::now();
    let batch_block_proof = batch_block_circuit_data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    batch_block_circuit_data.verify(batch_block_proof).unwrap();
}
