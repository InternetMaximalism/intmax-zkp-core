pub mod process_smt;
pub mod utils;

#[test]
fn test_verify_process_proof_by_plonky2() {
    use plonky2::{
        field::types::Sample,
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::super::{
        gadgets::process::process_smt::SparseMerkleProcessProofTarget,
        goldilocks_poseidon::PoseidonSparseMerkleTreeMemory,
    };

    use crate::utils::hash::GoldilocksHashOut;

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    // type F = GoldilocksField;
    const N_LEVELS: usize = 16;

    let mut tree = PoseidonSparseMerkleTreeMemory::new(Default::default(), Default::default());
    let key1 = GoldilocksHashOut::from_u128(1);
    let value1 = GoldilocksHashOut::from_u128(2);

    let mut witness = tree.insert(key1, value1).unwrap();

    use rand::Rng;
    let zero = GoldilocksHashOut::default();

    let mut rng = rand::thread_rng();
    let round: u8 = rng.gen();
    println!("round = {round}");

    for _ in 0..round {
        let random_key = HashOut::rand();
        let random_value = HashOut::rand();
        let op_id: u8 = rng.gen();
        let op_id = op_id % 2;
        match op_id {
            0 => {
                // insert, update or remove
                witness = tree.set(random_key.into(), random_value.into()).unwrap();
            }
            1 => {
                // remove or noop
                witness = tree.set(random_key.into(), zero).unwrap();
            }
            _ => {
                unreachable!()
            }
        }
    }

    // let witness = tree.set(key1, HashOut::rand().into()).unwrap();
    dbg!(&witness);
    witness.check();
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // assert!(N_LEVELS > witness.siblings.len());
    let target = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(&mut builder, N_LEVELS);
    builder.register_public_inputs(&target.old_key.elements);
    builder.register_public_inputs(&target.old_value.elements);
    builder.register_public_inputs(&target.new_key.elements);
    builder.register_public_inputs(&target.new_value.elements);
    builder.register_public_inputs(&target.old_root.elements);
    builder.register_public_inputs(&target.new_root.elements);
    let data = builder.build::<C>();

    // dbg!(&data.common);

    let mut pw = PartialWitness::new();
    target.set_witness(&mut pw, &witness);
    let proof = data.prove(pw).unwrap();

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}

#[test]
fn test_verify_process_proof2_by_plonky2() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::sparse_merkle_tree::{
        gadgets::process::process_smt::SparseMerkleProcessProofTarget,
        goldilocks_poseidon::{
            LayeredLayeredPoseidonSparseMerkleTree, LayeredLayeredPoseidonSparseMerkleTreeMemory,
            NodeDataMemory, PoseidonSparseMerkleTreeMemory,
        },
    };
    use crate::{utils::hash::GoldilocksHashOut, zkdsa::account::private_key_to_account};

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    // type F = GoldilocksField;
    const LOG_MAX_N_USERS: usize = 32;

    let sender1_private_key = HashOut {
        elements: [
            GoldilocksField::from_canonical_u64(17426287337377512978),
            GoldilocksField::from_canonical_u64(8703645504073070742),
            GoldilocksField::from_canonical_u64(11984317793392655464),
            GoldilocksField::from_canonical_u64(9979414176933652180),
        ],
    };
    let sender1_account = private_key_to_account(sender1_private_key);

    let sender2_private_key = HashOut {
        elements: [
            GoldilocksField::from_canonical_u64(17814943904840276189),
            GoldilocksField::from_canonical_u64(12088887497349422745),
            GoldilocksField::from_canonical_u64(1199609976110004574),
            GoldilocksField::from_canonical_u64(13794990519201211279),
        ],
    };
    let sender2_account = private_key_to_account(sender2_private_key);

    let mut world_state_tree =
        PoseidonSparseMerkleTreeMemory::new(NodeDataMemory::default(), Default::default());

    let mut sender1_user_asset_tree: LayeredLayeredPoseidonSparseMerkleTreeMemory =
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
    let zero = GoldilocksHashOut::ZERO;

    let witness = sender1_user_asset_tree
        .set(key1.0, key1.1, key1.2, value1)
        .unwrap();
    witness.0.check();
    witness.1.check();
    witness.2.check();

    let witness = sender1_user_asset_tree
        .set(key2.0, key2.1, key2.2, value2)
        .unwrap();
    witness.0.check();
    witness.1.check();
    witness.2.check();

    let witness = world_state_tree
        .set(
            sender1_account.address.to_hash_out().into(),
            sender1_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();
    witness.check();

    let witness = sender1_user_asset_tree
        .set(key2.0, key2.1, key2.2, zero)
        .unwrap();
    witness.0.check();
    witness.1.check();
    witness.2.check();
    let witness = sender1_user_asset_tree
        .set(key1.0, key1.1, key1.2, zero)
        .unwrap();
    witness.0.check();
    witness.1.check();
    witness.2.check();

    let sender2_user_asset_root = GoldilocksHashOut::rand(); // sender2_user_asset_tree.get_root()
    let witness = world_state_tree
        .set(
            sender2_account.address.to_hash_out().into(),
            sender2_user_asset_root,
        )
        .unwrap();
    witness.check();

    let witness = world_state_tree
        .set(
            sender1_account.address.to_hash_out().into(),
            sender1_user_asset_tree.get_root().unwrap(),
        )
        .unwrap();
    dbg!(&witness);
    witness.check();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_gate_row = Some(83);

    assert!(LOG_MAX_N_USERS > witness.siblings.len());
    let target =
        SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(&mut builder, LOG_MAX_N_USERS);
    builder.register_public_inputs(&target.old_key.elements);
    builder.register_public_inputs(&target.old_value.elements);
    builder.register_public_inputs(&target.new_key.elements);
    builder.register_public_inputs(&target.new_value.elements);
    builder.register_public_inputs(&target.old_root.elements);
    builder.register_public_inputs(&target.new_root.elements);
    let data = builder.build::<C>();

    // dbg!(&data.common);

    let mut pw = PartialWitness::new();
    let start = std::time::Instant::now();
    target.set_witness(&mut pw, &witness);
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
