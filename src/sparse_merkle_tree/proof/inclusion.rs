use std::fmt::Debug;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMerkleInclusionProof<K, V, I> {
    /// `root` is the value of the root node when given key is searched for.
    pub root: I,

    /// `found` is whether given key was found ot not.
    pub found: bool,

    /// `key` is the searching key.
    pub key: K,

    /// If given key was found, `value` is the value corresponding to the key. Otherwise, (`value`)
    /// is default value.
    pub value: V,

    /// If given key was not found, (`not_found_key`, `not_found_value`) is the last leaf found
    /// while searching for that key.
    pub not_found_key: K,

    /// If given key was not found, (`not_found_key`, `not_found_value`) is the last leaf found
    /// while searching for that key.
    pub not_found_value: V,

    /// `siblings` is the witness for the (non-)inclusion of given key.
    pub siblings: Vec<I>,

    /// `is_old0 = true` means the last leaf found while searching for that key is null node.
    pub is_old0: bool,
}

// impl<K: Default, V: Default, I: Default> Default for SparseMerkleInclusionProof<K, V, I> {
//     fn default() -> Self {
//         Self::with_root(I::default())
//     }
// }

impl<K: Default, V: Default, I> SparseMerkleInclusionProof<K, V, I> {
    pub fn with_root(root: I) -> Self {
        Self {
            root,
            found: false,
            key: K::default(),
            value: V::default(),
            not_found_key: K::default(),
            not_found_value: V::default(),
            siblings: vec![],
            is_old0: true,
        }
    }
}

impl<K, V, I> SparseMerkleInclusionProof<K, V, I> {
    pub fn check(&self) -> bool {
        // TODO
        true
    }
}

#[test]
fn test_serialize_merkle_proof() {
    use super::super::goldilocks_poseidon::GoldilocksHashOut;

    let merkle_proof = SparseMerkleInclusionProof {
        root: GoldilocksHashOut::from_u32(1),
        found: true,
        key: GoldilocksHashOut::from_u32(2),
        value: GoldilocksHashOut::from_u32(3),
        not_found_key: GoldilocksHashOut::from_u32(5),
        not_found_value: GoldilocksHashOut::from_u32(6),
        siblings: vec![GoldilocksHashOut::from_u32(4)],
        is_old0: false,
    };
    let encoded_merkle_proof = serde_json::to_string(&merkle_proof).unwrap();
    let decoded_merkle_proof: SparseMerkleInclusionProof<_, _, _> =
        serde_json::from_str(&encoded_merkle_proof).unwrap();
    assert_eq!(decoded_merkle_proof, merkle_proof);
}
