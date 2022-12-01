pub mod verify_smt;

#[test]
#[cfg(feature = "std")]
fn test_verify_inclusion_proof_by_plonky2() {
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use super::super::{
        gadgets::verify::verify_smt::SparseMerkleInclusionProofTarget,
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
    let key2 = GoldilocksHashOut::from_u128(12);
    let value2 = GoldilocksHashOut::from_u128(1);
    let key3 = GoldilocksHashOut::from_u128(5);
    let value3 = GoldilocksHashOut::from_u128(51);

    tree.insert(key1, value1).unwrap();
    tree.insert(key2, value2).unwrap();
    tree.insert(key3, value3).unwrap();

    let witness = tree.find(&key3).unwrap();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let target: SparseMerkleInclusionProofTarget<N_LEVELS> =
        SparseMerkleInclusionProofTarget::add_virtual_to::<F, H, D>(&mut builder);
    let data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    target.set_witness(&mut pw, &witness, true);
    let proof = data.prove(pw).unwrap();

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
