use intmax_zkp_core::sparse_merkle_tree::{
    goldilocks_poseidon::{
        GoldilocksHashOut, PoseidonNodeHash, PoseidonSparseMerkleTreeMemory, Wrapper,
    },
    node_data::Node,
    node_hash::NodeHash,
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64, Sample},
    },
    hash::hash_types::{HashOut, HashOutTarget},
};

type K = GoldilocksHashOut;
type V = GoldilocksHashOut;
type I = GoldilocksHashOut;

struct ProcessorLoop {
    top: bool,
    old0: bool,
    new1: bool,
    bot: bool,
    na: bool,
    upd: bool,
}

fn main() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let zero = GoldilocksHashOut::default();
    let mut tree = PoseidonSparseMerkleTreeMemory::new(Default::default(), Default::default());
    let key1 = GoldilocksHashOut::from_u128(1);
    let value1 = GoldilocksHashOut::from_u128(2);
    let mut proof = tree.insert(key1, value1).unwrap();
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
    let siblings = proof.siblings;
    dbg!(&siblings);
    let fnc: [u8; 2] = proof.fnc.into();
    dbg!(&fnc);
    let old_key = proof.old_key;
    let old_value = proof.old_value;
    let new_value = proof.new_value;
    let new_key = proof.new_key;

    let num_levels = siblings.len();
    let enabled = fnc[0] * fnc[1] != 0;

    let hash1_old = PoseidonNodeHash::calc_node_hash(Node::Leaf(old_key, old_value));
    let hash1_new = PoseidonNodeHash::calc_node_hash(Node::Leaf(new_key, new_value));
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

    // let mut sm: Vec<ProcessorLoop> = Vec::with_capacity(num_levels);
    // for i in 0..num_levels {
    //     let st = smt_processor_sm(xors[i], is_old0, lev_ins[i], is_insert_or_remove_op, prev);
    //     sm.push(st);
    //     prev = st;
    // }

    // // flag = sm[nLevels-1].st_na + sm[nLevels-1].st_new1 + sm[nLevels-1].st_old0 + sm[nLevels-1].st_upd;
    // let flag = sm[num_levels - 1].na
    //     ^ sm[num_levels - 1].new1
    //     ^ sm[num_levels - 1].old0
    //     ^ sm[num_levels - 1].upd;

    // // flag === 1;
    // assert!(flag);

    // // component levels[nLevels];
    // // for (i=nLevels-1; i != -1; i--)
    // let mut prev_level = (default_hash, default_hash);
    // for i in (0..num_levels).rev() {
    //     let (old_child, new_child) = prev_level;
    //     prev_level = smt_processor_level::<F, H, D>(
    //         sm[i],
    //         siblings[i],
    //         hash1_old,
    //         hash1_new,
    //         n2b_new[i],
    //         old_child,
    //         new_child,
    //     );
    // }
}

pub fn smt_lev_ins(
    is_insert_op: bool,
    siblings: Vec<Wrapper<HashOut<GoldilocksField>>>,
) -> Vec<bool> {
    let num_levels = siblings.len();
    let zero = GoldilocksField::ZERO;
    let mut is_zeros = siblings
        .iter()
        .map(|sibling| {
            sibling.0
                == HashOut {
                    elements: [zero; 4],
                }
        })
        .collect::<Vec<_>>();

    is_zeros.reverse();

    // The last level must always have a sibling of 0. If not, then it cannot be inserted.
    assert!(is_zeros[0]);

    let mut lev_ins = vec![];
    let mut done = vec![]; // Indicates if the insLevel has already been detected.

    lev_ins.push(!is_zeros[1]); // lev_ins[0]
    done.push(lev_ins[0]); // done[0]
    for i in 1..(num_levels - 1) {
        let last_done = done.last().unwrap();

        // levIns[i] <== (1-done[i - 1])*(1-isZero[i+1].out);
        lev_ins.push(!is_zeros[i + 1] & !last_done);

        // done[i] <== levIns[i] + done[i - 1];
        done.push(lev_ins.last().unwrap() ^ last_done);
    }

    assert!(done.last().unwrap());

    // lev_ins[num_levels - 1] = 1 - done[num_levels - 2];
    lev_ins.push(!done.last().unwrap());

    lev_ins.reverse();

    lev_ins
}

// convert u64 to little endian bits arrary
fn to_le_64(mut x: u64) -> Vec<bool> {
    let mut r = vec![];
    while x > 0 {
        r.push(x & 1 == 1);
        x >>= 1;
    }
    r.extend(std::iter::repeat(false).take(64 - r.len()));
    assert_eq!(r.len(), 64);
    return r;
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
