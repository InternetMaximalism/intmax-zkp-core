use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};

use crate::{
    rollup::gadgets::deposit_block::DepositInfo,
    sparse_merkle_tree::{
        gadgets::verify::verify_smt::SmtInclusionProof,
        goldilocks_poseidon::WrappedHashOut,
        goldilocks_poseidon::{
            LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory, PoseidonSparseMerkleTree,
        },
    },
};

#[allow(clippy::type_complexity)]
pub fn make_deposit_proof(
    deposit_list: &[DepositInfo<GoldilocksField>],
    index: Option<usize>,
) -> (
    WrappedHashOut<GoldilocksField>,
    Option<(
        SmtInclusionProof<GoldilocksField>,
        SmtInclusionProof<GoldilocksField>,
    )>,
) {
    let mut inner_deposit_tree =
        LayeredLayeredPoseidonSparseMerkleTree::<NodeDataMemory>::default();
    for leaf in deposit_list {
        inner_deposit_tree
            .set(
                leaf.receiver_address.to_hash_out().into(),
                leaf.contract_address.to_hash_out().into(),
                leaf.variable_index.into(),
                HashOut::from_partial(&[leaf.amount]).into(),
            )
            .unwrap();
    }

    let inner_deposit_root = inner_deposit_tree.get_root();

    let mut deposit_tree = PoseidonSparseMerkleTree::<NodeDataMemory>::default();
    let pseudo_tx_hash = Default::default();
    deposit_tree
        .set(pseudo_tx_hash, inner_deposit_root)
        .unwrap();

    let deposit_root = deposit_tree.get_root();

    if index.is_none() {
        return (deposit_root, None);
    }

    let index = index.unwrap();

    let target_leaf = deposit_list[index];

    let inner_deposit_tree: PoseidonSparseMerkleTree<NodeDataMemory> = inner_deposit_tree.into();
    let deposit_proof2 = inner_deposit_tree
        .find(&target_leaf.receiver_address.to_hash_out().into())
        .unwrap();

    debug_assert!(deposit_proof2.found);

    let deposit_proof1 = deposit_tree.find(&pseudo_tx_hash).unwrap();

    debug_assert!(deposit_proof1.found);

    (deposit_root, Some((deposit_proof1, deposit_proof2)))
}
