use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::Hasher,
};

use crate::{
    merkle_tree::tree::{get_merkle_proof, MerkleProof},
    rollup::gadgets::deposit_block::DepositInfo,
    sparse_merkle_tree::{
        gadgets::verify::verify_smt::SmtInclusionProof,
        goldilocks_poseidon::{
            LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory, PoseidonSparseMerkleTree,
            RootDataMemory,
        },
    },
    zkdsa::account::Address,
};

#[allow(clippy::type_complexity)]
pub fn make_partial_deposit_proof(
    deposit_list: &[DepositInfo<GoldilocksField>],
    num_log_txs: usize,
) -> MerkleProof<GoldilocksField> {
    let mut inner_deposit_tree =
        LayeredLayeredPoseidonSparseMerkleTree::<NodeDataMemory, RootDataMemory>::default();
    for leaf in deposit_list {
        inner_deposit_tree
            .set(
                leaf.receiver_address.to_hash_out().into(),
                leaf.contract_address.to_hash_out().into(),
                leaf.variable_index.to_hash_out().into(),
                HashOut::from_partial(&[leaf.amount]).into(),
            )
            .unwrap();
    }

    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root =
        PoseidonHash::two_to_one(*inner_deposit_tree.get_root().unwrap(), deposit_nonce);

    get_merkle_proof(&[deposit_diff_root.into()], 0, num_log_txs)
}

#[allow(clippy::type_complexity)]
pub fn make_deposit_proof(
    deposit_list: &[DepositInfo<GoldilocksField>],
    receiver_address: Address<GoldilocksField>,
    num_log_txs: usize,
) -> (
    MerkleProof<GoldilocksField>,
    SmtInclusionProof<GoldilocksField>,
) {
    let mut inner_deposit_tree =
        LayeredLayeredPoseidonSparseMerkleTree::<NodeDataMemory, RootDataMemory>::default();
    for leaf in deposit_list {
        inner_deposit_tree
            .set(
                leaf.receiver_address.to_hash_out().into(),
                leaf.contract_address.to_hash_out().into(),
                leaf.variable_index.to_hash_out().into(),
                HashOut::from_partial(&[leaf.amount]).into(),
            )
            .unwrap();
    }

    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root =
        PoseidonHash::two_to_one(*inner_deposit_tree.get_root().unwrap(), deposit_nonce);

    let deposit_proof1 = get_merkle_proof(&[deposit_diff_root.into()], 0, num_log_txs);

    let inner_deposit_tree: PoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory> =
        inner_deposit_tree.into();
    let deposit_proof2 = inner_deposit_tree
        .find(&receiver_address.to_hash_out().into())
        .unwrap();

    debug_assert!(deposit_proof2.found);

    (deposit_proof1, deposit_proof2)
}
