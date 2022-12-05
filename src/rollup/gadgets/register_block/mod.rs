use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::sparse_merkle_tree::{
    gadgets::process::{
        process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
        utils::{get_process_merkle_proof_role, ProcessMerkleProofRoleTarget},
    },
    goldilocks_poseidon::WrappedHashOut,
};

#[derive(Clone, Debug)]
pub struct RegisterBlockProofTarget<const N_LOG_MAX_USERS: usize, const N_REGISTERS: usize> {
    pub latest_account_process_proofs:
        [SparseMerkleProcessProofTarget<N_LOG_MAX_USERS>; N_REGISTERS], // input
    pub old_latest_account_digest: HashOutTarget, // input
    pub new_latest_account_digest: HashOutTarget, // output
    pub current_block_number: Target,             // input
}

impl<const N_LOG_MAX_USERS: usize, const N_REGISTERS: usize>
    RegisterBlockProofTarget<N_LOG_MAX_USERS, N_REGISTERS>
{
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let mut latest_account_process_proofs = vec![];
        for _ in 0..N_REGISTERS {
            let targets = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder);

            latest_account_process_proofs.push(targets);
        }

        let old_latest_account_digest = builder.add_virtual_hash();
        let current_block_number = builder.add_virtual_target();
        builder.range_check(current_block_number, 32);
        let new_latest_account_digest = verify_valid_register_block::<F, H, D, N_LOG_MAX_USERS>(
            builder,
            &latest_account_process_proofs,
            old_latest_account_digest,
            current_block_number,
        );

        Self {
            latest_account_process_proofs: latest_account_process_proofs.try_into().unwrap(),
            old_latest_account_digest,
            new_latest_account_digest,
            current_block_number,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        latest_account_process_proofs: &[SmtProcessProof<F>],
        old_latest_account_digest: WrappedHashOut<F>,
        current_block_number: u32,
    ) -> WrappedHashOut<F> {
        pw.set_hash_target(self.old_latest_account_digest, *old_latest_account_digest);
        pw.set_target(
            self.current_block_number,
            F::from_canonical_u32(current_block_number),
        );
        let mut prev_latest_account_root = old_latest_account_digest;
        assert!(latest_account_process_proofs.len() <= self.latest_account_process_proofs.len());
        for (proof_t, proof) in self
            .latest_account_process_proofs
            .iter()
            .zip(latest_account_process_proofs.iter())
        {
            assert_eq!(proof.old_root, prev_latest_account_root);
            prev_latest_account_root = proof.new_root;
            proof_t.set_witness(pw, proof);
        }

        let default_proof = SmtProcessProof::with_root(prev_latest_account_root);
        for proof_t in self
            .latest_account_process_proofs
            .iter()
            .skip(latest_account_process_proofs.len())
        {
            proof_t.set_witness(pw, &default_proof);
        }

        prev_latest_account_root
    }
}

/// Returns `new_latest_account_digest`
pub fn verify_valid_register_block<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
    const N_LOG_MAX_USERS: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    latest_account_process_proofs: &[SparseMerkleProcessProofTarget<N_LOG_MAX_USERS>],
    old_latest_account_digest: HashOutTarget,
    current_block_number: Target,
) -> HashOutTarget {
    let zero = builder.zero();
    let constant_true = builder._true();
    let mut prev_latest_account_digest = old_latest_account_digest;
    for proof_t in latest_account_process_proofs {
        let ProcessMerkleProofRoleTarget {
            is_insert_or_no_op,
            is_not_no_op,
            ..
        } = get_process_merkle_proof_role(builder, proof_t.fnc);
        builder.connect(is_insert_or_no_op.target, constant_true.target);

        builder.connect_hashes(proof_t.old_root, prev_latest_account_digest);

        let old_last_block_number = proof_t.old_value.elements[0];
        builder.connect(proof_t.old_value.elements[1], zero);
        builder.connect(proof_t.old_value.elements[2], zero);
        builder.connect(proof_t.old_value.elements[3], zero);
        let new_last_block_number = proof_t.new_value.elements[0];
        builder.connect(proof_t.new_value.elements[1], zero);
        builder.connect(proof_t.new_value.elements[2], zero);
        builder.connect(proof_t.new_value.elements[3], zero);

        let expected_new_last_block_number =
            builder._if(is_not_no_op, current_block_number, old_last_block_number);
        builder.connect(expected_new_last_block_number, new_last_block_number);

        prev_latest_account_digest = proof_t.new_root;
    }

    prev_latest_account_digest
}

#[test]
fn test_register_block() {
    use std::time::Instant;

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
                GoldilocksHashOut, LayeredLayeredPoseidonSparseMerkleTree,
                LayeredLayeredPoseidonSparseMerkleTreeMemory, NodeDataMemory,
                PoseidonSparseMerkleTree, PoseidonSparseMerkleTreeMemory, WrappedHashOut,
            },
            proof::SparseMerkleInclusionProof,
        },
        transaction::{
            block_header::{get_block_hash, BlockHeader},
            circuits::make_user_proof_circuit,
            gadgets::merge::MergeProof,
        },
        zkdsa::account::{private_key_to_account, PublicKey},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const N_LOG_MAX_USERS: usize = 3;
    const N_LOG_MAX_TXS: usize = 3;
    const N_LOG_MAX_CONTRACTS: usize = 3;
    const N_LOG_MAX_VARIABLES: usize = 3;
    const N_LOG_TXS: usize = 2;
    const N_LOG_RECIPIENTS: usize = 3;
    const N_LOG_CONTRACTS: usize = 3;
    const N_LOG_VARIABLES: usize = 3;
    const N_REGISTERS: usize = 2;
    const N_DIFFS: usize = 2;
    const N_MERGES: usize = 2;

    let mut world_state_tree =
        PoseidonSparseMerkleTreeMemory::new(NodeDataMemory::default(), Default::default());

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

    let mut sender1_user_asset_tree: LayeredLayeredPoseidonSparseMerkleTreeMemory =
        LayeredLayeredPoseidonSparseMerkleTree::new(Default::default(), Default::default());

    let mut sender1_tx_diff_tree: LayeredLayeredPoseidonSparseMerkleTreeMemory =
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
            GoldilocksField::from_canonical_u64(15657143458229430356),
            GoldilocksField::from_canonical_u64(6012455030006979790),
            GoldilocksField::from_canonical_u64(4280058849535143691),
            GoldilocksField::from_canonical_u64(5153662694263190591),
        ],
    };
    dbg!(&sender2_private_key);
    let sender2_account = private_key_to_account(sender2_private_key);
    let sender2_address = sender2_account.address.0;

    let node_data = NodeDataMemory::default();
    let mut sender2_user_asset_tree =
        PoseidonSparseMerkleTree::new(node_data.clone(), Default::default());

    let mut sender2_tx_diff_tree =
        LayeredLayeredPoseidonSparseMerkleTreeMemory::new(node_data.clone(), Default::default());

    world_state_tree
        .set(
            sender2_address.into(),
            sender2_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();

    let prev_approved_world_state_digest = world_state_tree.get_root().unwrap();

    let mut deposit_sender2_tree =
        LayeredLayeredPoseidonSparseMerkleTree::new(node_data, Default::default());

    deposit_sender2_tree
        .set(sender2_address.into(), key1.1, key1.2, value1)
        .unwrap();
    deposit_sender2_tree
        .set(sender2_address.into(), key2.1, key2.2, value2)
        .unwrap();

    let deposit_sender2_tree: PoseidonSparseMerkleTreeMemory = deposit_sender2_tree.into();

    let merge_inclusion_proof2 = deposit_sender2_tree.find(&sender2_address.into()).unwrap();

    // `merge_inclusion_proof2` の root を `diff_root`, `hash(diff_root, nonce)` の値を `tx_hash` とよぶ.
    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root = merge_inclusion_proof2.root;
    let deposit_tx_hash = PoseidonHash::two_to_one(*deposit_diff_root, deposit_nonce).into();

    let merge_inclusion_proof1 = get_merkle_proof(&[deposit_tx_hash], 0, N_LOG_TXS);

    let default_hash = HashOut::ZERO;
    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    let default_merkle_root = get_merkle_proof(&[], 0, N_LOG_TXS).root;
    let prev_block_number = 1;
    let prev_block_header = BlockHeader {
        block_number: prev_block_number,
        prev_block_header_digest: default_hash,
        transactions_digest: *default_merkle_root,
        deposit_digest: *merge_inclusion_proof1.root,
        proposed_world_state_digest: *prev_approved_world_state_digest,
        approved_world_state_digest: *prev_approved_world_state_digest,
        latest_account_digest: default_hash,
    };

    let block_hash = get_block_hash(&prev_block_header);

    // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    let deposit_merge_key = PoseidonHash::two_to_one(*deposit_tx_hash, block_hash).into();

    let merge_process_proof = sender2_user_asset_tree
        .set(deposit_merge_key, merge_inclusion_proof2.value)
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

    let mut sender2_user_asset_tree: LayeredLayeredPoseidonSparseMerkleTreeMemory =
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
    user_tx_proofs.push(sender1_tx_proof);
    world_state_process_proofs.push(sender2_world_state_process_proof);
    user_tx_proofs.push(sender2_tx_proof);

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_gate_row = Some(529); // xors in SparseMerkleProcessProof in DepositBlock

    // deposit block
    let deposit_block_target: RegisterBlockProofTarget<N_LOG_MAX_USERS, N_REGISTERS> =
        RegisterBlockProofTarget::add_virtual_to::<F, H, D>(&mut builder);
    let circuit_data = builder.build::<C>();

    let block_number = prev_block_number + 1;

    let new_accounts: Vec<PublicKey<F>> = vec![];

    let mut latest_account_tree: PoseidonSparseMerkleTreeMemory =
        PoseidonSparseMerkleTree::new(Default::default(), Default::default());

    let mut latest_account_register_process_proofs = vec![];
    for public_key in new_accounts {
        latest_account_register_process_proofs.push(
            latest_account_tree
                .set(public_key.into(), GoldilocksHashOut::from_u32(block_number))
                .unwrap(),
        );
    }

    let mut pw = PartialWitness::new();
    deposit_block_target.set_witness::<F, H, D>(
        &mut pw,
        &latest_account_register_process_proofs,
        prev_block_header.latest_account_digest.into(),
        block_number,
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
