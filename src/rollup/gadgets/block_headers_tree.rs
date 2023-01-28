use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    merkle_tree::gadgets::{get_merkle_root_target, MerkleProofTarget},
    transaction::gadgets::block_header::{get_block_hash_target, BlockHeaderTarget},
};

const LOG_MAX_N_BLOCKS: usize = 32;

pub fn calc_block_headers_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    prev_block_headers_proof_siblings: Vec<HashOutTarget>,
    prev_block_header: &BlockHeaderTarget,
) -> MerkleProofTarget {
    assert_eq!(prev_block_headers_proof_siblings.len(), LOG_MAX_N_BLOCKS);
    let zero = builder.zero();
    let default_hash = HashOutTarget::from_partial(&[], zero);

    let prev_block_number = prev_block_header.block_number;
    let prev_block_number_path = builder.split_le(prev_block_number, 32);

    // `block_number - 2` までの block header で作られた block headers tree の `block_number - 1` 番目の proof
    // この時点では, leaf の値は 0 である.
    let prev_block_headers_digest = get_merkle_root_target::<F, H, D>(
        builder,
        &prev_block_number_path,
        default_hash,
        &prev_block_headers_proof_siblings,
    );
    builder.connect_hashes(
        prev_block_headers_digest,
        prev_block_header.block_headers_digest,
    );
    // `block_number - 1` の block hash
    let prev_block_hash = get_block_hash_target::<F, H, D>(builder, prev_block_header);
    // `block_number - 1` までの block header で作られた block headers tree の `block_number - 1` 番目の proof
    let block_headers_digest = get_merkle_root_target::<F, H, D>(
        builder,
        &prev_block_number_path,
        prev_block_hash,
        &prev_block_headers_proof_siblings,
    );

    MerkleProofTarget {
        root: block_headers_digest,
        index: prev_block_number_path,
        value: prev_block_hash,
        siblings: prev_block_headers_proof_siblings,
    }
}
