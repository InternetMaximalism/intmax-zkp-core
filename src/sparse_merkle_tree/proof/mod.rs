pub mod common;
pub mod process;

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessMerkleProofRole {
    ProcessNoOp,   // [0, 0]
    ProcessUpdate, // [0, 1]
    ProcessInsert, // [1, 0]
    ProcessDelete, // [1, 1]
}

impl From<[bool; 2]> for ProcessMerkleProofRole {
    fn from(value: [bool; 2]) -> Self {
        match value {
            [false, false] => Self::ProcessNoOp,
            [false, true] => Self::ProcessUpdate,
            [true, false] => Self::ProcessInsert,
            [true, true] => Self::ProcessDelete,
        }
    }
}

impl TryFrom<u8> for ProcessMerkleProofRole {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ProcessNoOp),
            1 => Ok(Self::ProcessUpdate),
            2 => Ok(Self::ProcessInsert),
            3 => Ok(Self::ProcessDelete),
            _ => Err(anyhow::anyhow!("fail to parse")),
        }
    }
}

impl TryFrom<[u8; 2]> for ProcessMerkleProofRole {
    type Error = anyhow::Error;

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        match value {
            [0, 0] => Ok(Self::ProcessNoOp),
            [0, 1] => Ok(Self::ProcessUpdate),
            [1, 0] => Ok(Self::ProcessInsert),
            [1, 1] => Ok(Self::ProcessDelete),
            _ => Err(anyhow::anyhow!("fail to parse")),
        }
    }
}

impl From<ProcessMerkleProofRole> for [bool; 2] {
    fn from(value: ProcessMerkleProofRole) -> Self {
        match value {
            ProcessMerkleProofRole::ProcessNoOp => [false, false],
            ProcessMerkleProofRole::ProcessUpdate => [false, true],
            ProcessMerkleProofRole::ProcessInsert => [true, false],
            ProcessMerkleProofRole::ProcessDelete => [true, true],
        }
    }
}

impl From<ProcessMerkleProofRole> for u8 {
    fn from(value: ProcessMerkleProofRole) -> Self {
        match value {
            ProcessMerkleProofRole::ProcessNoOp => 0,
            ProcessMerkleProofRole::ProcessUpdate => 1,
            ProcessMerkleProofRole::ProcessInsert => 2,
            ProcessMerkleProofRole::ProcessDelete => 3,
        }
    }
}

impl From<ProcessMerkleProofRole> for [u8; 2] {
    fn from(value: ProcessMerkleProofRole) -> Self {
        match value {
            ProcessMerkleProofRole::ProcessNoOp => [0, 0],
            ProcessMerkleProofRole::ProcessUpdate => [0, 1],
            ProcessMerkleProofRole::ProcessInsert => [1, 0],
            ProcessMerkleProofRole::ProcessDelete => [1, 1],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMerkleProcessProof<K, V, I> {
    pub old_root: I,
    pub old_key: K,
    pub old_value: V,
    pub new_root: I,
    pub new_key: K,
    pub new_value: V,
    pub siblings: Vec<I>,
    pub is_old0: bool,
    pub fnc: ProcessMerkleProofRole,
}

// impl<K: Default, V: Default, I: Clone + Default> Default for SparseMerkleProcessProof<K, V, I> {
//     fn default() -> Self {
//         Self::with_root(I::default())
//     }
// }

impl<K: Default, V: Default, I: Clone> SparseMerkleProcessProof<K, V, I> {
    pub fn with_root(root: I) -> Self {
        Self {
            old_root: root.clone(),
            old_key: K::default(),
            old_value: V::default(),
            new_root: root,
            new_key: K::default(),
            new_value: V::default(),
            siblings: vec![],
            is_old0: true,
            fnc: ProcessMerkleProofRole::ProcessNoOp,
        }
    }
}

impl<K, V, I> SparseMerkleProcessProof<K, V, I> {
    pub fn check(&self) -> bool {
        // TODO
        true
    }
}

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
    use super::goldilocks_poseidon::GoldilocksHashOut;

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
    let result = serde_json::to_string(&merkle_proof).unwrap();
    dbg!(result);
}
