use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::HashOut,
        poseidon::{Poseidon, PoseidonHash},
    },
    plonk::config::Hasher,
};

use crate::{
    merkle_tree::tree::{get_merkle_proof, MerkleProof},
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
    num_log_txs: usize,
) -> (
    WrappedHashOut<GoldilocksField>,
    Option<(
        MerkleProof<GoldilocksField>,
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

    let deposit_nonce = HashOut::ZERO;
    let diff_root = PoseidonHash::two_to_one(*inner_deposit_tree.get_root(), deposit_nonce);

    let deposit_proof1 = get_merkle_proof(&[diff_root.into()], index.unwrap_or(0), num_log_txs);

    if index.is_none() {
        return (deposit_proof1.root, None);
    }

    let index = index.unwrap();

    let target_leaf = deposit_list[index];

    let inner_deposit_tree: PoseidonSparseMerkleTree<NodeDataMemory> = inner_deposit_tree.into();
    let deposit_proof2 = inner_deposit_tree
        .find(&target_leaf.receiver_address.to_hash_out().into())
        .unwrap();

    debug_assert!(deposit_proof2.found);

    (deposit_proof1.root, Some((deposit_proof1, deposit_proof2)))
}
