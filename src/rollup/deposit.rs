use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
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

// #[allow(clippy::type_complexity)]
// pub fn make_partial_deposit_proof(
//     deposit_list: &[DepositInfo<GoldilocksField>],
//     num_log_txs: usize,
// ) -> MerkleProof<GoldilocksField> {
//     let mut inner_deposit_tree =
//         LayeredLayeredPoseidonSparseMerkleTree::<NodeDataMemory, RootDataMemory>::default();
//     for leaf in deposit_list {
//         inner_deposit_tree
//             .set(
//                 leaf.receiver_address.to_hash_out().into(),
//                 leaf.contract_address.to_hash_out().into(),
//                 leaf.variable_index.to_hash_out().into(),
//                 HashOut::from_partial(&[leaf.amount]).into(),
//             )
//             .unwrap();
//     }

//     let deposit_nonce = HashOut::ZERO;
//     let deposit_diff_root =
//         PoseidonHash::two_to_one(*inner_deposit_tree.get_root().unwrap(), deposit_nonce);

//     get_merkle_proof(&[deposit_diff_root.into()], 0, num_log_txs)
// }

#[allow(clippy::type_complexity)]
pub fn make_deposit_proof(
    deposit_list: &[DepositInfo<GoldilocksField>],
    scroll_flag_list: &[DepositInfo<GoldilocksField>],
    polygon_flag_list: &[DepositInfo<GoldilocksField>],
    receiver_address: Address<GoldilocksField>,
    num_log_txs: usize,
) -> Vec<(
    MerkleProof<GoldilocksField>,
    SmtInclusionProof<GoldilocksField>,
)> {
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

    let mut inner_scroll_flag_tree =
        LayeredLayeredPoseidonSparseMerkleTree::<NodeDataMemory, RootDataMemory>::default();
    for leaf in scroll_flag_list {
        inner_scroll_flag_tree
            .set(
                leaf.receiver_address.to_hash_out().into(),
                leaf.contract_address.to_hash_out().into(),
                leaf.variable_index.to_hash_out().into(),
                HashOut::from_partial(&[leaf.amount]).into(),
            )
            .unwrap();
    }

    let mut inner_polygon_flag_tree =
        LayeredLayeredPoseidonSparseMerkleTree::<NodeDataMemory, RootDataMemory>::default();
    for leaf in polygon_flag_list {
        inner_polygon_flag_tree
            .set(
                leaf.receiver_address.to_hash_out().into(),
                leaf.contract_address.to_hash_out().into(),
                leaf.variable_index.to_hash_out().into(),
                HashOut::from_partial(&[leaf.amount]).into(),
            )
            .unwrap();
    }

    let chain_index = HashOut::from_partial(&[GoldilocksField::from_canonical_usize(0)]);
    let deposit_diff_root =
        PoseidonHash::two_to_one(*inner_deposit_tree.get_root().unwrap(), chain_index).into();

    let chain_index = HashOut::from_partial(&[GoldilocksField::from_canonical_usize(1)]);
    let scroll_flag_root =
        PoseidonHash::two_to_one(*inner_scroll_flag_tree.get_root().unwrap(), chain_index).into();

    let chain_index = HashOut::from_partial(&[GoldilocksField::from_canonical_usize(2)]);
    let polygon_flag_root =
        PoseidonHash::two_to_one(*inner_polygon_flag_tree.get_root().unwrap(), chain_index).into();

    let deposit_tree_roots = &[deposit_diff_root, scroll_flag_root, polygon_flag_root];
    let deposit_proof1 = get_merkle_proof(deposit_tree_roots, 0, num_log_txs);
    let deposit_proof1_scroll = get_merkle_proof(deposit_tree_roots, 1, num_log_txs);
    let deposit_proof1_polygon = get_merkle_proof(deposit_tree_roots, 2, num_log_txs);

    let inner_deposit_tree: PoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory> =
        inner_deposit_tree.into();
    let deposit_proof2 = inner_deposit_tree
        .find(&receiver_address.to_hash_out().into())
        .unwrap();

    let inner_scroll_flag_tree: PoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory> =
        inner_scroll_flag_tree.into();
    let deposit_proof2_scroll = inner_scroll_flag_tree
        .find(&receiver_address.to_hash_out().into())
        .unwrap();

    let inner_polygon_flag_tree: PoseidonSparseMerkleTree<NodeDataMemory, RootDataMemory> =
        inner_polygon_flag_tree.into();
    let deposit_proof2_polygon = inner_polygon_flag_tree
        .find(&receiver_address.to_hash_out().into())
        .unwrap();

    vec![
        (deposit_proof1, deposit_proof2),
        (deposit_proof1_scroll, deposit_proof2_scroll),
        (deposit_proof1_polygon, deposit_proof2_polygon),
    ]
}
