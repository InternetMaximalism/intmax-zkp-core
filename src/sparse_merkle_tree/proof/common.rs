use crate::sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut;
use plonky2::hash::hash_types::RichField;

pub(crate) fn smt_lev_ins<F: RichField>(
    is_insert_op: bool,
    siblings: &[WrappedHashOut<F>],
) -> Vec<bool> {
    let num_levels = siblings.len();
    let default_hash = WrappedHashOut::ZERO;
    let mut is_zeros = siblings
        .iter()
        .map(|sibling| *sibling == default_hash)
        .collect::<Vec<_>>();

    is_zeros.reverse();

    // if this is insert process, the last level of siblings must be 0.
    if is_insert_op {
        assert!(is_zeros[0]);
    }

    let mut lev_ins = vec![];
    let mut done = vec![]; // Indicates if the insLevel has already been detected.

    lev_ins.push(!is_zeros[1]); // lev_ins[0]
    done.push(lev_ins[0]); // done[0]
    for i in 1..(num_levels - 1) {
        let last_done = done.last().unwrap();

        // levIns[i] <== (1-done[i - 1])*(1-isZero[i+1].out);
        lev_ins.push(!is_zeros[i + 1] & !last_done);

        // done[i] <== levIns[i] + done[i - 1];
        done.push(*lev_ins.last().unwrap() || *last_done);
    }

    assert!(done.last().unwrap());

    // lev_ins[num_levels - 1] = 1 - done[num_levels - 2];
    lev_ins.push(!done.last().unwrap());

    lev_ins.reverse();

    lev_ins
}
