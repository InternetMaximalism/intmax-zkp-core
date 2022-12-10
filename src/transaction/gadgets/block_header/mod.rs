use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::poseidon::gadgets::poseidon_two_to_one;

use super::super::block_header::BlockHeader;

const N_LOG_MAX_BLOCKS: usize = 32;

#[derive(Clone, Debug)]
pub struct BlockHeaderTarget {
    pub block_number: Target, // u32
    pub block_headers_digest: HashOutTarget,
    pub transactions_digest: HashOutTarget,
    pub deposit_digest: HashOutTarget,
    pub proposed_world_state_digest: HashOutTarget,
    pub approved_world_state_digest: HashOutTarget,
    pub latest_account_digest: HashOutTarget,
}

impl BlockHeaderTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let block_number = builder.add_virtual_target();
        builder.range_check(block_number, N_LOG_MAX_BLOCKS);
        let block_headers_digest = builder.add_virtual_hash();
        let transactions_digest = builder.add_virtual_hash();
        let deposit_digest = builder.add_virtual_hash();
        let proposed_world_state_digest = builder.add_virtual_hash();
        let approved_world_state_digest = builder.add_virtual_hash();
        let latest_account_digest = builder.add_virtual_hash();

        Self {
            block_number,
            block_headers_digest,
            transactions_digest,
            deposit_digest,
            proposed_world_state_digest,
            approved_world_state_digest,
            latest_account_digest,
        }
    }

    pub fn set_witness<F: Field>(&self, pw: &mut impl Witness<F>, block_header: &BlockHeader<F>) {
        pw.set_target(
            self.block_number,
            F::from_canonical_u32(block_header.block_number),
        );
        pw.set_hash_target(self.block_headers_digest, block_header.block_headers_digest);
        pw.set_hash_target(self.transactions_digest, block_header.transactions_digest);
        pw.set_hash_target(self.deposit_digest, block_header.deposit_digest);
        pw.set_hash_target(
            self.proposed_world_state_digest,
            block_header.proposed_world_state_digest,
        );
        pw.set_hash_target(
            self.approved_world_state_digest,
            block_header.approved_world_state_digest,
        );
        pw.set_hash_target(
            self.latest_account_digest,
            block_header.latest_account_digest,
        );
    }
}

pub fn get_block_hash_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    block_header: &BlockHeaderTarget,
) -> HashOutTarget {
    let zero = builder.zero();

    let a = poseidon_two_to_one::<F, H, D>(
        builder,
        HashOutTarget::from_partial(&[block_header.block_number], zero),
        block_header.latest_account_digest,
    );
    let b = poseidon_two_to_one::<F, H, D>(
        builder,
        block_header.deposit_digest,
        block_header.transactions_digest,
    );
    let c = poseidon_two_to_one::<F, H, D>(builder, a, b);
    let d = poseidon_two_to_one::<F, H, D>(
        builder,
        block_header.proposed_world_state_digest,
        block_header.approved_world_state_digest,
    );
    let e = poseidon_two_to_one::<F, H, D>(builder, c, d);

    poseidon_two_to_one::<F, H, D>(builder, block_header.block_headers_digest, e)
}
