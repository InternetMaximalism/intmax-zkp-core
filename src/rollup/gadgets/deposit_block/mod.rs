use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use serde::{Deserialize, Serialize};

use crate::{
    sparse_merkle_tree::{
        gadgets::{
            common::conditionally_select,
            process::{
                process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
                utils::{
                    get_process_merkle_proof_role, verify_layered_smt_connection,
                    ProcessMerkleProofRoleTarget,
                },
            },
        },
        goldilocks_poseidon::GoldilocksHashOut,
    },
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositInfo<F: Field> {
    pub receiver_address: Address<F>,
    pub contract_address: Address<F>,
    pub variable_index: HashOut<F>,
    pub amount: F,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableDepositInfo {
    pub receiver_address: GoldilocksHashOut,
    pub contract_address: GoldilocksHashOut,
    pub variable_index: GoldilocksHashOut,
    pub amount: GoldilocksField,
}

impl From<SerializableDepositInfo> for DepositInfo<GoldilocksField> {
    fn from(value: SerializableDepositInfo) -> Self {
        Self {
            receiver_address: Address(value.receiver_address.0),
            contract_address: Address(value.contract_address.0),
            variable_index: value.variable_index.0,
            amount: value.amount,
        }
    }
}

impl<'de> Deserialize<'de> for DepositInfo<GoldilocksField> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = SerializableDepositInfo::deserialize(deserializer)?;

        Ok(raw.into())
    }
}

impl From<DepositInfo<GoldilocksField>> for SerializableDepositInfo {
    fn from(value: DepositInfo<GoldilocksField>) -> Self {
        SerializableDepositInfo {
            receiver_address: value.receiver_address.0.into(),
            contract_address: value.contract_address.0.into(),
            variable_index: value.variable_index.into(),
            amount: value.amount,
        }
    }
}

impl Serialize for DepositInfo<GoldilocksField> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = SerializableDepositInfo::from(*self);

        raw.serialize(serializer)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DepositInfoTarget {
    pub receiver_address: AddressTarget,
    pub contract_address: AddressTarget,
    pub variable_index: HashOutTarget,
    pub amount: Target,
}

impl DepositInfoTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let receiver_address = AddressTarget::add_virtual_to(builder);
        let contract_address = AddressTarget::add_virtual_to(builder);
        let variable_index = builder.add_virtual_hash();
        let amount = builder.add_virtual_target();

        Self {
            receiver_address,
            contract_address,
            variable_index,
            amount,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        value: DepositInfo<F>,
    ) {
        self.receiver_address
            .set_witness(pw, value.receiver_address);
        self.contract_address
            .set_witness(pw, value.contract_address);
        pw.set_hash_target(self.variable_index, value.variable_index);
        pw.set_target(self.amount, value.amount);
    }
}

#[derive(Clone, Debug)]
pub struct DepositBlockProofTarget<
    const D: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_DEPOSITS: usize,
> {
    pub deposit_process_proofs: [(
        SparseMerkleProcessProofTarget<N_LOG_RECIPIENTS>,
        SparseMerkleProcessProofTarget<N_LOG_CONTRACTS>,
        SparseMerkleProcessProofTarget<N_LOG_VARIABLES>,
    ); N_DEPOSITS], // input

    pub deposit_digest: HashOutTarget, // output
}

impl<
        const D: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_LOG_CONTRACTS: usize,
        const N_LOG_VARIABLES: usize,
        const N_DEPOSITS: usize,
    > DepositBlockProofTarget<D, N_LOG_RECIPIENTS, N_LOG_CONTRACTS, N_LOG_VARIABLES, N_DEPOSITS>
{
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let mut deposit_process_proofs = vec![];
        for _ in 0..N_DEPOSITS {
            let targets = (
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder),
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder),
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder),
            );

            deposit_process_proofs.push(targets);
        }

        let deposit_digest = deposit_process_proofs.last().unwrap().0.new_root;

        Self {
            deposit_process_proofs: deposit_process_proofs.try_into().unwrap(),
            deposit_digest,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        deposit_process_proofs: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
    ) {
        assert!(!deposit_process_proofs.is_empty());
        assert!(deposit_process_proofs.len() <= self.deposit_process_proofs.len());
        for (proof_t, proof) in self
            .deposit_process_proofs
            .iter()
            .zip(deposit_process_proofs.iter())
        {
            proof_t.0.set_witness(pw, &proof.0);
            proof_t.1.set_witness(pw, &proof.1);
            proof_t.2.set_witness(pw, &proof.2);
        }

        let latest_root = deposit_process_proofs.last().unwrap().0.new_root;
        let default_proof = SmtProcessProof::with_root(Default::default());
        let default_proof0 = SmtProcessProof::with_root(latest_root);
        for proof_t in self
            .deposit_process_proofs
            .iter()
            .skip(deposit_process_proofs.len())
        {
            proof_t.0.set_witness(pw, &default_proof0);
            proof_t.1.set_witness(pw, &default_proof);
            proof_t.2.set_witness(pw, &default_proof);
        }
    }
}

/// Returns `(block_tx_root, old_world_state_root, new_world_state_root)`
pub fn calc_deposit_digest<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    deposit_process_proofs: &[(
        SparseMerkleProcessProofTarget<N_LOG_RECIPIENTS>,
        SparseMerkleProcessProofTarget<N_LOG_CONTRACTS>,
        SparseMerkleProcessProofTarget<N_LOG_VARIABLES>,
    )],
) -> HashOutTarget {
    let zero = builder.zero();
    let mut deposit_digest = HashOutTarget {
        elements: [zero; 4],
    };
    for proof_t in deposit_process_proofs {
        let ProcessMerkleProofRoleTarget {
            is_insert_or_no_op,
            is_no_op,
            ..
        } = get_process_merkle_proof_role(builder, proof_t.2.fnc);
        let constant_true = builder._true();
        builder.connect(is_insert_or_no_op.target, constant_true.target);
        verify_layered_smt_connection(
            builder,
            proof_t.0.fnc,
            proof_t.0.old_value,
            proof_t.0.new_value,
            proof_t.1.old_root,
            proof_t.1.new_root,
        );
        verify_layered_smt_connection(
            builder,
            proof_t.1.fnc,
            proof_t.1.old_value,
            proof_t.1.new_value,
            proof_t.2.old_root,
            proof_t.2.new_root,
        );

        builder.connect_hashes(proof_t.0.old_root, deposit_digest);

        deposit_digest =
            conditionally_select(builder, deposit_digest, proof_t.0.new_root, is_no_op);
    }

    deposit_digest
}

#[test]
fn test_deposit_block() {
    use std::time::Instant;

    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, Field64},
        },
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
        rollup::gadgets::deposit_block::DepositInfo,
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
        zkdsa::{
            account::{private_key_to_account, Address},
            circuits::make_simple_signature_circuit,
        },
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
    const N_DEPOSITS: usize = 2;
    const N_DIFFS: usize = 2;
    const N_MERGES: usize = 2;

    let mut world_state_tree =
        PoseidonSparseMerkleTree::new(NodeDataMemory::default(), Default::default());

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

    let node_data = NodeDataMemory::default();
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
    let deposit_tx_hash = PoseidonHash::two_to_one(*merge_inclusion_proof2.root, deposit_nonce);

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

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_gate_row = Some(529); // xors in SparseMerkleProcessProof in DepositBlock

    // deposit block
    let deposit_block_target: DepositBlockProofTarget<
        D,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_DEPOSITS,
    > = DepositBlockProofTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher>(&mut builder);
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

    let deposit_list: Vec<DepositInfo<F>> = vec![DepositInfo {
        receiver_address: Address(sender2_address),
        contract_address: Address(*GoldilocksHashOut::from_u128(1)),
        variable_index: *GoldilocksHashOut::from_u128(0),
        amount: GoldilocksField::from_noncanonical_u64(1),
    }];

    let mut deposit_tree: LayeredLayeredPoseidonSparseMerkleTree<NodeDataMemory> =
        LayeredLayeredPoseidonSparseMerkleTree::new(Default::default(), Default::default());
    let deposit_process_proofs = deposit_list
        .iter()
        .map(|leaf| {
            deposit_tree
                .set(
                    leaf.receiver_address.0.into(),
                    leaf.contract_address.0.into(),
                    leaf.variable_index.into(),
                    HashOut::from_partial(&[leaf.amount]).into(),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();

    let mut pw = PartialWitness::new();
    deposit_block_target.set_witness::<F, H>(&mut pw, &deposit_process_proofs);

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
