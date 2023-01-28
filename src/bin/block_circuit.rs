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

    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let merge_and_purge_circuit = make_user_proof_circuit::<F, C, D>(config, rollup_constants);

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

    let user_tx_proofs = vec![sender1_tx_proof, sender2_tx_proof];

    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let zkdsa_circuit = make_simple_signature_circuit(config);

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

    let received_signature_proofs = vec![None, Some(sender2_received_signature_proof)];

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
