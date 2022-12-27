use std::hash::Hash;

use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

use crate::{
    merkle_tree::tree::{get_merkle_proof, get_merkle_root},
    sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct BlockHeader<F: Field> {
    pub block_number: u32,
    pub prev_block_hash: HashOut<F>,
    pub block_headers_digest: HashOut<F>, // block header tree root
    pub transactions_digest: HashOut<F>,  // state diff tree root
    pub deposit_digest: HashOut<F>,       // deposit tree root
    pub proposed_world_state_digest: HashOut<F>,
    pub approved_world_state_digest: HashOut<F>,
    pub latest_account_digest: HashOut<F>, // latest account tree
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "WrappedHashOut<F>: Deserialize<'de>"))]
pub struct SerializableBlockHeader<F: RichField> {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub block_number: u32,
    pub prev_block_hash: WrappedHashOut<F>,
    pub block_headers_digest: WrappedHashOut<F>,
    pub transactions_digest: WrappedHashOut<F>,
    pub deposit_digest: WrappedHashOut<F>,
    pub proposed_world_state_digest: WrappedHashOut<F>,
    pub approved_world_state_digest: WrappedHashOut<F>,
    pub latest_account_digest: WrappedHashOut<F>,
}

impl<F: RichField> From<SerializableBlockHeader<F>> for BlockHeader<F> {
    fn from(value: SerializableBlockHeader<F>) -> Self {
        Self {
            block_number: value.block_number,
            prev_block_hash: *value.prev_block_hash,
            block_headers_digest: *value.block_headers_digest,
            transactions_digest: *value.transactions_digest,
            deposit_digest: *value.deposit_digest,
            proposed_world_state_digest: *value.proposed_world_state_digest,
            approved_world_state_digest: *value.approved_world_state_digest,
            latest_account_digest: *value.latest_account_digest,
        }
    }
}

impl<'de, F: RichField> Deserialize<'de> for BlockHeader<F> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = SerializableBlockHeader::deserialize(deserializer)?;

        Ok(raw.into())
    }
}

impl<F: RichField> From<BlockHeader<F>> for SerializableBlockHeader<F> {
    fn from(value: BlockHeader<F>) -> Self {
        Self {
            block_number: value.block_number,
            prev_block_hash: value.prev_block_hash.into(),
            block_headers_digest: value.block_headers_digest.into(),
            transactions_digest: value.transactions_digest.into(),
            deposit_digest: value.deposit_digest.into(),
            proposed_world_state_digest: value.proposed_world_state_digest.into(),
            approved_world_state_digest: value.approved_world_state_digest.into(),
            latest_account_digest: value.latest_account_digest.into(),
        }
    }
}

impl<F: RichField> Serialize for BlockHeader<F> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = SerializableBlockHeader::from(self.clone());

        raw.serialize(serializer)
    }
}

impl<F: RichField> BlockHeader<F> {
    pub fn new(log_num_txs_in_block: usize) -> Self {
        let default_hash = HashOut::ZERO;

        // transaction tree と deposit tree の深さは同じ.
        let default_merkle_digest = get_merkle_proof(&[], 0, log_num_txs_in_block).root;

        Self {
            block_number: 0,
            prev_block_hash: default_hash,
            block_headers_digest: default_hash,
            transactions_digest: *default_merkle_digest,
            deposit_digest: *default_merkle_digest,
            proposed_world_state_digest: default_hash,
            approved_world_state_digest: default_hash,
            latest_account_digest: default_hash,
        }
    }
}

pub fn get_block_hash<F: RichField>(block_header: &BlockHeader<F>) -> HashOut<F> {
    let a = PoseidonHash::two_to_one(
        HashOut::from_partial(&[F::from_canonical_u32(block_header.block_number)]),
        block_header.latest_account_digest,
    );
    let b = PoseidonHash::two_to_one(
        block_header.deposit_digest,
        block_header.transactions_digest,
    );
    let c = PoseidonHash::two_to_one(a, b);
    let d = PoseidonHash::two_to_one(
        block_header.proposed_world_state_digest,
        block_header.approved_world_state_digest,
    );
    let e = PoseidonHash::two_to_one(c, d);

    PoseidonHash::two_to_one(block_header.block_headers_digest, e)
}

pub fn get_block_header_tree_proof<F: RichField>(
    block_hashes: &[WrappedHashOut<F>],
    new_block_hash: WrappedHashOut<F>,
    depth: usize,
) -> (Vec<WrappedHashOut<F>>, WrappedHashOut<F>, WrappedHashOut<F>) {
    let current_index = block_hashes.len();
    let old_proof = get_merkle_proof(block_hashes, current_index, depth);
    let new_root = get_merkle_root(current_index, new_block_hash, &old_proof.siblings);

    (old_proof.siblings, old_proof.root, new_root)
}
