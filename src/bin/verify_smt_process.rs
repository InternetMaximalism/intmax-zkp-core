use std::time::Instant;

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

use intmax_zkp_core::sparse_merkle_tree::{
    gadgets::process::process_smt::SparseMerkleProcessProofTarget,
    goldilocks_poseidon::{GoldilocksHashOut, PoseidonSparseMerkleTreeMemory},
};

const D: usize = 2; // extension degree
type C = PoseidonGoldilocksConfig;
type H = <C as GenericConfig<D>>::InnerHasher;
type F = <C as GenericConfig<D>>::F;
// type F = GoldilocksField;
const N_LEVELS: usize = 256;

fn main() {
    loop {
        benchmark();

        // let mut handlers = vec![];
        // for _ in 0..2 {
        //     let handler = std::thread::spawn(|| {
        //         benchmark();
        //     });
        //     handlers.push(handler);
        // }

        // for handler in handlers {
        //     handler.join().unwrap();
        // }
    }
}

fn benchmark() {
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
        if rng.gen::<bool>() {
            // insert or update (or remove)
            witness = tree.set(random_key.into(), random_value.into()).unwrap();
        } else {
            // remove or noop
            witness = tree.set(random_key.into(), zero).unwrap();
        }
    }

    if rng.gen::<bool>() {
        let random_value = HashOut::rand();
        if rng.gen::<bool>() {
            // update
            witness = tree.set(key1, random_value.into()).unwrap();
        } else {
            // remove
            witness = tree.set(key1, zero).unwrap();
        }
    }

    println!("fnc = {:?}", witness.fnc);
    println!("is_old0 = {:?}", witness.is_old0);

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

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

    println!("start proving");
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => {
            dbg!(serde_json::to_string(&witness).unwrap());
            panic!("{}", x);
        }
    }
}
