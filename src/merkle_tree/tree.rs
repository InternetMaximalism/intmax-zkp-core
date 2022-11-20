use plonky2::{
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};

pub fn log2_ceil(value: usize) -> u32 {
    assert!(value != 0, "The first argument must be a positive number.");

    if value == 1 {
        return 0;
    }

    let mut log_value = 1;
    let mut tmp_value = value - 1;
    while tmp_value > 1 {
        tmp_value /= 2;
        log_value += 1;
    }

    log_value
}

/// `2^depth` 個の leaf からなる Merkle tree に `leaves` で与えられた leaf を左から詰め,
/// 残りは 0 で埋める. Merkle root と与えられた `index` に関する siblings を返す.
/// ただし, siblings は root から遠い順に並べる.
/// Returns `(siblings, root)`
pub fn get_merkle_proof<F: RichField>(
    leaves: &[HashOut<F>],
    index: usize,
    depth: usize,
) -> (Vec<HashOut<F>>, HashOut<F>) {
    let num_leaves = leaves.len().max(index).next_power_of_two();
    let log_num_leaves = log2_ceil(num_leaves) as usize;
    let mut nodes = leaves.to_vec();
    nodes.resize(num_leaves, HashOut::ZERO);

    let mut siblings = vec![HashOut::ZERO]; // initialize by zero hashes
    for _ in 1..depth {
        let last_zero: HashOut<F> = *siblings.last().unwrap();
        siblings.push(PoseidonHash::two_to_one(last_zero, last_zero));
    }

    let mut rest_index = index;
    for sibling in siblings.iter_mut().take(log_num_leaves) {
        let _ = std::mem::replace(sibling, nodes[rest_index ^ 1]);

        let mut new_nodes: Vec<HashOut<F>> = vec![];
        for j in 0..(nodes.len() / 2) {
            new_nodes.push(PoseidonHash::two_to_one(nodes[2 * j], nodes[2 * j + 1]));
        }

        rest_index >>= 1;
        nodes = new_nodes;
    }

    assert_eq!(nodes.len(), 1);
    let mut root = nodes[0];
    for sibling in siblings.iter().skip(log_num_leaves) {
        // log_num_leaves 層より上は sibling が必ず右側にくる.
        root = PoseidonHash::two_to_one(root, *sibling);
    }

    (siblings, root)
}

/// 与えられた leaf `(index, value)` と `siblings` から Merkle root を計算する.
pub fn get_merkle_root<F: RichField>(
    index: usize,
    value: HashOut<F>,
    siblings: &[HashOut<F>],
) -> HashOut<F> {
    let mut root = value;
    let mut rest_index = index;
    for sibling in siblings {
        let (left, right) = if rest_index & 1 == 0 {
            (root, *sibling)
        } else {
            (*sibling, root)
        };
        root = PoseidonHash::two_to_one(left, right);
        rest_index >>= 1;
    }

    root
}

#[test]
fn test_get_block_hash_tree_proofs() {
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    type F = GoldilocksField;

    let mut leaves = vec![0, 10, 20, 30, 40, 0]
        .into_iter()
        .map(|i| HashOut {
            elements: [F::from_canonical_u32(i), F::ZERO, F::ZERO, F::ZERO],
        })
        .collect::<Vec<HashOut<_>>>();
    const N_LEVELS: usize = 10;
    let index = leaves.len() - 1;
    let (siblings, old_root) = get_merkle_proof(&leaves, index, N_LEVELS);
    dbg!(old_root);

    // TODO: `index` 番目の要素が変化しても siblings は同じであることを確かめる.
    let new_leaf = HashOut {
        elements: [F::from_canonical_u32(50), F::ZERO, F::ZERO, F::ZERO],
    };
    let new_root = get_merkle_root(index, new_leaf, &siblings);

    leaves[index] = new_leaf;
    let (actual_siblings, actual_new_root) = get_merkle_proof(&leaves, index, N_LEVELS);
    assert_eq!(siblings, actual_siblings);
    assert_eq!(new_root, actual_new_root);
}
