use crate::sparse_merkle_tree::{
    gadgets::process::process_smt::SmtProcessProof, goldilocks_poseidon::WrappedHashOut,
    node_data::Node, node_hash::NodeHash, proof::common::smt_lev_ins,
};
use plonky2::hash::hash_types::RichField;
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

impl<K, V, I> SparseMerkleProcessProof<K, V, I> {
    pub fn check(&self) -> bool {
        // TODO
        true
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

pub fn verify_smt_process_proof<
    F: RichField,
    H: NodeHash<WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>>,
>(
    proof: &SmtProcessProof<F>,
) {
    let siblings = &proof.siblings;
    dbg!(siblings);
    let is_old0 = proof.is_old0;

    let num_levels = siblings.len();
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

    let hash1_old = H::calc_node_hash(Node::Leaf(old_key, old_value));
    let hash1_new = H::calc_node_hash(Node::Leaf(new_key, new_value));
    let n2b_old = old_key
        .elements
        .into_iter()
        .flat_map(|e| to_le_64(e.to_canonical_u64()))
        .collect::<Vec<_>>();
    let n2b_new = new_key
        .elements
        .into_iter()
        .flat_map(|e| to_le_64(e.to_canonical_u64()))
        .collect::<Vec<_>>();

    let lev_ins = smt_lev_ins(enabled, siblings);

    let xors = n2b_old
        .iter()
        .zip(n2b_new.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();

    let mut prev = ProcessorLoop {
        top: enabled,
        old0: false,
        new1: false,
        bot: false,
        na: !enabled,
        upd: false,
    };

    let mut sm: Vec<ProcessorLoop> = Vec::with_capacity(num_levels);
    for i in 0..num_levels {
        let is_insert_or_remove_op = fnc == ProcessMerkleProofRole::ProcessInsert;
        let st = smt_processor_sm(xors[i], is_old0, lev_ins[i], is_insert_or_remove_op, prev);
        sm.push(st);
        prev = st;
    }

    {
        // flag = sm[nLevels-1].st_na + sm[nLevels-1].st_new1 + sm[nLevels-1].st_old0 + sm[nLevels-1].st_upd;
        let flag = sm[num_levels - 1].na
            || sm[num_levels - 1].new1
            || sm[num_levels - 1].old0
            || sm[num_levels - 1].upd;

        // flag === 1;
        assert!(flag);
    }

    // component levels[nLevels];
    // for (i=nLevels-1; i != -1; i--)
    let default_hash = WrappedHashOut::ZERO;
    let mut prev_level = (default_hash, default_hash);
    for i in (0..num_levels).rev() {
        let (old_child, new_child) = prev_level;
        prev_level = smt_processor_level::<F, H>(
            sm[i],
            siblings[i],
            hash1_old,
            hash1_new,
            n2b_new[i],
            old_child,
            new_child,
        );
    }

    if enabled {
        assert_eq!(prev_level.0, old_root);
        assert_eq!(prev_level.1, new_root);
    } else {
        assert_eq!(old_root, new_root);
        assert_eq!(old_value, new_value);
    }
    if fnc == ProcessMerkleProofRole::ProcessUpdate || !enabled {
        assert_eq!(old_key, new_key);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn smt_processor_level<
    F: RichField,
    H: NodeHash<WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>>,
>(
    st: ProcessorLoop,
    sibling: WrappedHashOut<F>,
    old1_leaf: WrappedHashOut<F>,
    new1_leaf: WrappedHashOut<F>,
    new_lr_bit: bool,
    old_child: WrappedHashOut<F>,
    new_child: WrappedHashOut<F>,
) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
    let ProcessorLoop {
        top: st_top,
        old0: st_old0,
        new1: st_new1,
        bot: st_bot,
        upd: st_upd,
        ..
    } = st;

    let default_hash = WrappedHashOut::ZERO;

    let old_hash_out = {
        let internal_node = if new_lr_bit {
            Node::Internal(sibling, old_child)
        } else {
            Node::Internal(old_child, sibling)
        };

        H::calc_node_hash(internal_node)
    };

    // aux[0] <== old1leaf * (st_bot + st_new1 + st_upd);
    // oldRoot <== aux[0] + oldProofHash.out * st_top;
    let old_root = if st_bot || st_new1 || st_upd {
        old1_leaf
    } else if st_top {
        old_hash_out
    } else {
        default_hash
    };

    // aux[1] <== newChild * (st_top + st_bot);
    // newSwitcher.L <== aux[1] + new1leaf*st_new1;
    let new_left_child = if st_top || st_bot {
        new_child
    } else if st_new1 {
        new1_leaf
    } else {
        default_hash
    };

    // aux[2] <== sibling*st_top;
    // newSwitcher.R <== aux[2] + old1leaf*st_new1;
    let new_right_child = if st_top {
        sibling
    } else if st_new1 {
        old1_leaf
    } else {
        default_hash
    };

    let new_hash_out = {
        let internal_node = if new_lr_bit {
            Node::Internal(new_right_child, new_left_child)
        } else {
            Node::Internal(new_left_child, new_right_child)
        };

        H::calc_node_hash(internal_node)
    };

    // aux[3] <== newProofHash.out * (st_top + st_bot + st_new1);
    // newRoot <==  aux[3] + new1leaf * (st_old0 + st_upd);
    let new_root = if st_top || st_bot || st_new1 {
        new_hash_out
    } else if st_old0 || st_upd {
        new1_leaf
    } else {
        default_hash
    };

    (old_root, new_root)
}

pub(crate) fn smt_processor_sm(
    xor: bool,
    is0: bool,
    lev_ins: bool,
    is_insert_or_remove_op: bool,
    prev: ProcessorLoop,
) -> ProcessorLoop {
    // aux1 = prev_top * levIns
    let aux1 = prev.top && lev_ins;

    // aux2 = prev_top * levIns * fnc[0]
    let aux2 = aux1 && is_insert_or_remove_op;

    // st_top = prev_top * (1-levIns)
    //    = + prev_top
    //      - prev_top * levIns
    let top = prev.top && !lev_ins;

    // st_old0 = prev_top * levIns * is0 * fnc[0]
    //      = + prev_top * levIns * is0 * fnc[0]         (= aux2 * is0)
    let old0 = aux2 && is0;

    // st_new1 = prev_top * levIns * (1-is0)*fnc[0] * xor   +  prev_bot*xor =
    //    = + prev_top * levIns *       fnc[0] * xor     (= aux2     * xor)
    //      - prev_top * levIns * is0 * fnc[0] * xor     (= st_old0  * xor)
    //      + prev_bot *                         xor     (= prev_bot * xor)
    let aux2_minus_old0 = aux2 && !is0;
    let aux2_minus_old0_plus_prev_bot = aux2_minus_old0 || prev.bot;
    let new1 = aux2_minus_old0_plus_prev_bot && xor;

    // st_bot = prev_top * levIns * (1-is0)*fnc[0] * (1-xor) + prev_bot*(1-xor);
    //    = + prev_top * levIns *       fnc[0]
    //      - prev_top * levIns * is0 * fnc[0]
    //      - prev_top * levIns *       fnc[0] * xor
    //      + prev_top * levIns * is0 * fnc[0] * xor
    //      + prev_bot
    //      - prev_bot *                         xor
    let bot = aux2_minus_old0_plus_prev_bot && !xor;

    // st_upd = prev_top * (1-fnc[0]) *levIns;
    //    = + prev_top * levIns
    //      - prev_top * levIns * fnc[0]

    let upd = aux1 && !is_insert_or_remove_op;

    // st_na = prev_new1 + prev_old0 + prev_na + prev_upd;
    //    = + prev_new1
    //      + prev_old0
    //      + prev_na
    //      + prev_upd
    // NOTICE: or の代わりに add を使うとうまくいかない.
    // let prev_new1_plus_prev_old0 = builder.add(prev.new1.target, prev.old0.target);
    // let prev_new1_plus_prev_old0_plus_prev_na =
    //     builder.add(prev_new1_plus_prev_old0, prev.na.target);
    // let na =
    //     BoolTarget::new_unsafe(builder.add(prev_new1_plus_prev_old0_plus_prev_na, prev.upd.target));
    // builder.assert_bool(na);
    let prev_new1_plus_prev_old0 = prev.new1 || prev.old0;
    let prev_new1_plus_prev_old0_plus_prev_na = prev_new1_plus_prev_old0 || prev.na;
    let na = prev_new1_plus_prev_old0_plus_prev_na || prev.upd;

    ProcessorLoop {
        top,
        old0,
        new1,
        bot,
        na,
        upd,
    }
}

// convert u64 to little endian bits arrary
fn to_le_64(x: u64) -> Vec<bool> {
    let mut x = x;
    let mut r = vec![];
    while x > 0 {
        r.push(x & 1 == 1);
        x >>= 1;
    }

    r.resize(64, false);
    assert_eq!(r.len(), 64);

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_le() {
        assert_eq!(to_le_64(1), vec![true]);
        assert_eq!(to_le_64(2), vec![false, true]);
        assert_eq!(to_le_64(3), vec![true, true]);
        assert_eq!(to_le_64(8), vec![false, false, false, true]);
    }
}
