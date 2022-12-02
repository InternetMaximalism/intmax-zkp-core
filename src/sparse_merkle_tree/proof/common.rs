use plonky2::{hash::hash_types::RichField, plonk::config::GenericHashOut};

/// `levIns[i] == 1` if its level and all the descendants have a sibling of 0 and
/// the parent level has a non-zero sibling. Consider that the root level always has
/// a parent with a non-zero sibling.
///
/// https://github.com/iden3/circomlib/blob/master/circuits/smt/smtlevins.circom
pub(crate) fn smt_lev_ins<I: Default + Eq>(siblings: &[I], enabled: bool) -> Vec<bool> {
    let mut is_zeros = siblings
        .iter()
        .map(|sibling| I::default().eq(sibling))
        .collect::<Vec<_>>();

    // The last level must have a zero sibling.
    if enabled {
        assert!(is_zeros.last().unwrap());
    }

    is_zeros.reverse();
    is_zeros.push(false);

    if cfg!(debug_assertion) {
        assert!(is_zeros[0]);
    }

    let mut lev_ins = vec![];

    let mut last_done = false;
    for i in 0..siblings.len() {
        // levIns[i] <== (1-done[i - 1])*(1-isZero[i+1].out);
        lev_ins.push(!is_zeros[i + 1] && !last_done);

        // done[i] <== levIns[i] + done[i - 1];
        last_done = last_done || !is_zeros[i + 1];
    }

    lev_ins.reverse();

    if cfg!(debug_assertion) {
        assert_eq!(lev_ins.len(), siblings.len());
    }

    lev_ins
}

// convert u8 to little endian bits arrary
pub fn to_le_bits(x: u8) -> Vec<bool> {
    let mut x = x;
    let mut r = vec![];
    while x > 0 {
        r.push(x & 1 == 1);
        x >>= 1;
    }

    r.resize(8, false);

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_le() {
        assert_eq!(to_le_bits(1), vec![true]);
        assert_eq!(to_le_bits(2), vec![false, true]);
        assert_eq!(to_le_bits(3), vec![true, true]);
        assert_eq!(to_le_bits(8), vec![false, false, false, true]);
    }
}

pub fn first_different_bit_index<F: RichField, H: GenericHashOut<F>>(
    old_key: H,
    new_key: H,
) -> Option<usize> {
    let n2b_old = old_key.to_bytes().into_iter().flat_map(to_le_bits);
    let n2b_new = new_key.to_bytes().into_iter().flat_map(to_le_bits);

    n2b_old
        .zip(n2b_new)
        .enumerate()
        .find(|(_, (old, new))| old ^ new)
        .map(|(index, _)| index)
}
