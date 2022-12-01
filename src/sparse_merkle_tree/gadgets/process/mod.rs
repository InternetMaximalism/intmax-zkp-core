pub mod process_smt;
pub mod utils;

#[test]
#[cfg(feature = "std")]
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
        goldilocks_poseidon::{GoldilocksHashOut, PoseidonSparseMerkleTreeMemory},
    };

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
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // assert!(N_LEVELS > witness.siblings.len());
    let target: SparseMerkleProcessProofTarget<N_LEVELS> =
        SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(&mut builder);
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
