use std::fmt::Debug;

use crate::{
    sparse_merkle_tree::{
        goldilocks_poseidon::PoseidonNodeHash, node_data::Node, node_hash::NodeHash,
        proof::common::smt_lev_ins,
    },
    utils::{common::to_le_bits, hash::GoldilocksHashOut},
};
use plonky2::{hash::hash_types::RichField, plonk::config::GenericHashOut};
use serde::{Deserialize, Serialize};

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

impl SparseMerkleProcessProof<GoldilocksHashOut, GoldilocksHashOut, GoldilocksHashOut> {
    pub fn check(&self) {
        verify_smt_process_proof::<_, _, _, _, PoseidonNodeHash>(self);
    }
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProcessorLoop {
    top: bool,
    old0: bool,
    new1: bool,
    bot: bool,
    na: bool,
    upd: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessorStatus {
    Top,
    Bottom,
    OldIsZero,
    NewOne,
    Update,
    Na,
}

pub fn verify_smt_process_proof<
    F: RichField,
    K: Default + GenericHashOut<F>,
    V: Copy + Default + Eq + Debug,
    I: Copy + Default + Eq + Debug,
    H: NodeHash<K, V, I>,
>(
    proof: &SparseMerkleProcessProof<K, V, I>,
) {
    let enabled = proof.fnc != ProcessMerkleProofRole::ProcessNoOp;

    // remove proof は old と new をひっくり返せば insert proof になる
    let (fnc, old_key, old_value, old_root, new_key, new_value, new_root) =
        if proof.fnc == ProcessMerkleProofRole::ProcessDelete {
            (
                ProcessMerkleProofRole::ProcessInsert,
                proof.new_key,
                proof.new_value,
                proof.new_root,
                proof.old_key,
                proof.old_value,
                proof.old_root,
            )
        } else {
            (
                proof.fnc,
                proof.old_key,
                proof.old_value,
                proof.old_root,
                proof.new_key,
                proof.new_value,
                proof.new_root,
            )
        };

    if cfg!(debug_assertion) {
        assert_ne!(fnc, ProcessMerkleProofRole::ProcessDelete);
    }

    // old key の Merkle path
    let n2b_old = old_key
        .to_bytes()
        .into_iter()
        .flat_map(to_le_bits)
        .collect::<Vec<_>>();
    // new key の Merkle path
    let n2b_new = new_key
        .to_bytes()
        .into_iter()
        .flat_map(to_le_bits)
        .collect::<Vec<_>>();
    assert_eq!(n2b_old.len(), n2b_new.len());

    let mut siblings = proof.siblings.clone();
    assert!(siblings.len() < n2b_new.len()); // siblings の長さは Merkle path の長さより小さい
    siblings.resize(n2b_new.len(), I::default());
    let lev_ins = smt_lev_ins(&siblings, enabled);

    let mut prev = if enabled {
        ProcessorStatus::Top
    } else {
        ProcessorStatus::Na
    };
    let is_insert_or_remove_op = fnc == ProcessMerkleProofRole::ProcessInsert;
    let is_old0 = proof.is_old0;
    let mut sm = Vec::with_capacity(lev_ins.len());
    for i in 0..lev_ins.len() {
        let st = smt_processor_sm(
            prev,
            n2b_old[i] ^ n2b_new[i],
            is_old0,
            lev_ins[i],
            is_insert_or_remove_op,
        );
        sm.push(st);
        prev = st;
    }

    // 最後の status は top でも btn　でもない.
    {
        let last_status = *sm.last().unwrap();
        assert!(last_status != ProcessorStatus::Top && last_status != ProcessorStatus::Bottom);
    }

    let num_levels = n2b_new.len();
    let top_level_root = calc_old_new_root::<_, _, _, H>(
        (old_key, old_value),
        (new_key, new_value),
        &siblings,
        &n2b_new,
        &sm,
        num_levels,
    );

    if enabled {
        assert_eq!(top_level_root.0, old_root);
        assert_eq!(top_level_root.1, new_root);
    } else {
        assert_eq!(old_root, new_root);
        assert_eq!(old_value, new_value);
    }
    if fnc == ProcessMerkleProofRole::ProcessUpdate || !enabled {
        assert_eq!(old_key, new_key);
    }
}

/// Returns `(old_root, new_root)`
pub(crate) fn calc_old_new_root<K, V, I: Copy + Default + Eq + Debug, H: NodeHash<K, V, I>>(
    (old_key, old_value): (K, V),
    (new_key, new_value): (K, V),
    siblings: &[I],
    n2b_new: &[bool],
    sm: &[ProcessorStatus],
    num_levels: usize,
) -> (I, I) {
    let default_hash = I::default();
    let old1_leaf = H::calc_node_hash(Node::Leaf(old_key, old_value));
    let new1_leaf = H::calc_node_hash(Node::Leaf(new_key, new_value));
    let mut prev_level_root = (default_hash, default_hash);
    for i in (0..num_levels).rev() {
        let child_position = n2b_new[i];
        let (old_child, new_child) = prev_level_root;
        let old_hash_out = {
            let internal_node = if child_position {
                Node::Internal(siblings[i], old_child)
            } else {
                Node::Internal(old_child, siblings[i])
            };

            H::calc_node_hash(internal_node)
        };

        // aux[0] <== old1leaf * (st_bot + st_new1 + st_upd);
        // oldRoot <== aux[0] + oldProofHash.out * st_top;
        let old_root = match sm[i] {
            ProcessorStatus::Top => old_hash_out,
            ProcessorStatus::Bottom => old1_leaf,
            ProcessorStatus::NewOne => old1_leaf,
            ProcessorStatus::Update => old1_leaf,
            _ => default_hash,
        };

        // aux[1] <== newChild * (st_top + st_bot);
        // newSwitcher.L <== aux[1] + new1leaf*st_new1;
        let new_left_child = match sm[i] {
            ProcessorStatus::Top => new_child,
            ProcessorStatus::Bottom => new_child,
            ProcessorStatus::NewOne => new1_leaf,
            _ => default_hash,
        };

        // aux[2] <== sibling*st_top;
        // newSwitcher.R <== aux[2] + old1leaf*st_new1;
        let new_right_child = match sm[i] {
            ProcessorStatus::Top => siblings[i],
            ProcessorStatus::NewOne => old1_leaf,
            _ => default_hash,
        };

        let new_hash_out = {
            let internal_node = if child_position {
                Node::Internal(new_right_child, new_left_child)
            } else {
                Node::Internal(new_left_child, new_right_child)
            };

            H::calc_node_hash(internal_node)
        };

        // aux[3] <== newProofHash.out * (st_top + st_bot + st_new1);
        // newRoot <==  aux[3] + new1leaf * (st_old0 + st_upd);
        let new_root = match sm[i] {
            ProcessorStatus::Top => new_hash_out,
            ProcessorStatus::Bottom => new_hash_out,
            ProcessorStatus::NewOne => new_hash_out,
            ProcessorStatus::OldIsZero => new1_leaf,
            ProcessorStatus::Update => new1_leaf,
            _ => default_hash,
        };

        prev_level_root = (old_root, new_root);
    }

    prev_level_root
}

/// https://github.com/iden3/circomlib/blob/master/circuits/smt/smtprocessorsm.circom#L53-L90
pub(crate) fn smt_processor_sm(
    prev: ProcessorStatus,
    is_different_bit: bool,
    is_old0: bool,
    is_inserting_level: bool,
    is_insert_or_remove_op: bool,
) -> ProcessorStatus {
    match prev {
        ProcessorStatus::Top => {
            if !is_inserting_level {
                ProcessorStatus::Top
            } else if !is_insert_or_remove_op {
                ProcessorStatus::Update
            } else if is_old0 {
                ProcessorStatus::OldIsZero
            } else if is_different_bit {
                ProcessorStatus::NewOne
            } else {
                ProcessorStatus::Bottom
            }
        }
        ProcessorStatus::Bottom => {
            if is_different_bit {
                ProcessorStatus::NewOne
            } else {
                ProcessorStatus::Bottom
            }
        }
        _ => ProcessorStatus::Na,
    }
}
