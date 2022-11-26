use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    merkle_tree::gadgets::{get_merkle_root_target, MerkleProofTarget},
    sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut,
    transaction::{
        block_header::BlockHeader,
        gadgets::block_header::{get_block_hash_target, BlockHeaderTarget},
    },
};

const N_LOG_MAX_BLOCKS: usize = 32;

#[derive(Clone, Debug)]
pub struct BlockProofTarget {
    pub block_header: BlockHeaderTarget,
    pub prev_block_header_proof: MerkleProofTarget<N_LOG_MAX_BLOCKS>,
    pub prev_block_hash: HashOutTarget,
    pub prev_block_header_digest: HashOutTarget,
    pub block_hash: HashOutTarget,
}

impl BlockProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let block_header = BlockHeaderTarget::add_virtual_to::<F, H, D>(builder);

        // `block_number -　1` までの block header で block header tree を作る.
        let prev_block_header_proof = MerkleProofTarget::add_virtual_to::<F, H, D>(builder);
        let prev_block_hash = builder.add_virtual_hash();
        let prev_block_header_digest = get_merkle_root_target::<F, H, D>(
            builder,
            prev_block_header_proof.index,
            prev_block_hash,
            &prev_block_header_proof.siblings,
        );
        let block_hash = get_block_hash_target::<F, H, D>(builder, &block_header);

        BlockProofTarget {
            block_header,
            prev_block_header_proof,
            prev_block_hash,
            prev_block_header_digest,
            block_hash,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        block_header: BlockHeader<F>,
        block_header_siblings: &[WrappedHashOut<F>],
        prev_block_hash: WrappedHashOut<F>,
    ) {
        self.prev_block_header_proof.set_witness(
            pw,
            block_header.block_number as usize - 1,
            prev_block_hash,
            block_header_siblings,
        );
        self.block_header.set_witness(pw, &block_header);
        pw.set_hash_target(self.prev_block_hash, *prev_block_hash);
    }
}
