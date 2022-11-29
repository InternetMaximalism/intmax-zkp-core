use intmax_zkp_core::sparse_merkle_tree::goldilocks_poseidon::{
    GoldilocksHashOut, NodeDataMemory, PoseidonSparseMerkleTree,
};
use plonky2::{field::types::Sample, hash::hash_types::HashOut};

fn main() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let zero = GoldilocksHashOut::default();
    let mut tree: PoseidonSparseMerkleTree<NodeDataMemory> =
        PoseidonSparseMerkleTree::new(Default::default(), Default::default());
    let key1 = GoldilocksHashOut::from_u128(1);
    let value1 = GoldilocksHashOut::from_u128(2);
    let mut proof = tree.insert(key1, value1).unwrap();
    dbg!(proof);
    for _ in 0..10 {
        let random_key = HashOut::rand();
        let random_value = HashOut::rand();
        let op_id: u8 = rng.gen();
        let op_id = op_id % 2;
        match op_id {
            0 => {
                // insert, update or remove
                proof = tree.set(random_key.into(), random_value.into()).unwrap();
                assert!(proof.check());
            }
            1 => {
                // remove or noop
                proof = tree.set(random_key.into(), zero).unwrap();
                assert!(proof.check());
            }
            _ => {
                panic!()
            }
        }
    }
}
