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

use crate::{
    merkle_tree::tree::{get_merkle_proof, get_merkle_proof_with_zero, get_merkle_root},
    utils::hash::{SerializableHashOut, WrappedHashOut},
};

use super::circuits::MergeAndPurgeTransitionPublicInputs;

const LOG_MAX_N_BLOCKS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct BlockHeader<F: Field> {
    #[serde(
        serialize_with = "serialize_hex_u32",
        deserialize_with = "deserialize_hex_u32"
    )]
    pub block_number: u32,
    #[serde(with = "SerializableHashOut")]
    pub prev_block_hash: HashOut<F>,
    #[serde(with = "SerializableHashOut")]
    pub block_headers_digest: HashOut<F>, // block header tree root
    #[serde(with = "SerializableHashOut")]
    pub transactions_digest: HashOut<F>, // state diff tree root
    #[serde(with = "SerializableHashOut")]
    pub deposit_digest: HashOut<F>, // deposit tree root
    #[serde(with = "SerializableHashOut")]
    pub proposed_world_state_digest: HashOut<F>,
    #[serde(with = "SerializableHashOut")]
    pub approved_world_state_digest: HashOut<F>,
    #[serde(with = "SerializableHashOut")]
    pub latest_account_digest: HashOut<F>, // latest account tree
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
struct HexU32(pub u32);

impl Serialize for HexU32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw_value = format!("0x{}", hex::encode(self.0.to_be_bytes()));

        raw_value.serialize(serializer)
    }
}

fn serialize_hex_u32<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    HexU32(*value).serialize(serializer)
}

impl<'de> Deserialize<'de> for HexU32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw_value = String::deserialize(deserializer)?;
        let value = {
            let raw_without_prefix = raw_value.strip_prefix("0x").ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "fail to strip 0x-prefix: given value {raw_value} does not start with 0x",
                ))
            })?;
            let bytes = hex::decode(raw_without_prefix).map_err(|err| {
                serde::de::Error::custom(format!("fail to parse a hex string: {err}"))
            })?;

            u32::from_be_bytes(bytes.try_into().map_err(|err| {
                serde::de::Error::custom(format!("fail to parse to u32: {:?}", err))
            })?)
        };

        Ok(HexU32(value))
    }
}

fn deserialize_hex_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = HexU32::deserialize(deserializer)?;

    Ok(value.0)
}

impl<F: RichField> BlockHeader<F> {
    pub fn new(log_num_txs_in_block: usize) -> Self {
        let default_hash = HashOut::ZERO;

        // transaction tree と deposit tree の深さは同じ.
        let default_interior_deposit_digest = default_hash;
        let default_deposit_digest = get_merkle_proof_with_zero::<F, PoseidonHash>(
            &[],
            0,
            log_num_txs_in_block,
            default_interior_deposit_digest,
        )
        .root;
        let default_tx_hash = MergeAndPurgeTransitionPublicInputs::default().tx_hash;
        let default_transactions_digest = get_merkle_proof_with_zero::<F, PoseidonHash>(
            &[],
            0,
            log_num_txs_in_block,
            *default_tx_hash,
        )
        .root;
        let default_block_headers_digest =
            get_merkle_proof::<F, PoseidonHash>(&[], 0, LOG_MAX_N_BLOCKS).root;

        Self {
            block_number: 0,
            prev_block_hash: default_hash,
            block_headers_digest: default_block_headers_digest,
            transactions_digest: default_transactions_digest,
            deposit_digest: default_deposit_digest,
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
    let old_proof = get_merkle_proof::<F, PoseidonHash>(
        &block_hashes.iter().map(|v| v.0).collect::<Vec<_>>(),
        current_index,
        depth,
    );
    let new_root = get_merkle_root::<F, PoseidonHash, usize>(
        &current_index,
        *new_block_hash,
        &old_proof.siblings,
    );

    (
        old_proof
            .siblings
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<_>>(),
        old_proof.root.into(),
        new_root.into(),
    )
}

#[cfg(test)]
mod tests {
    use crate::transaction::block_header::BlockHeader;
    use crate::utils::hash::WrappedHashOut;

    #[test]
    fn test_serde_block_header() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        type F = GoldilocksField;

        let block_header = BlockHeader {
            block_number: 0,
            prev_block_hash: *WrappedHashOut::from_u32(1),
            block_headers_digest: *WrappedHashOut::from_u32(2),
            transactions_digest: *WrappedHashOut::from_u32(3),
            deposit_digest: *WrappedHashOut::from_u32(4),
            proposed_world_state_digest: *WrappedHashOut::from_u32(5),
            approved_world_state_digest: *WrappedHashOut::from_u32(6),
            latest_account_digest: *WrappedHashOut::from_u32(7),
        };
        let encoded_block_header = serde_json::to_string(&block_header).unwrap();
        let expected_encoded_block_header = "{\"block_number\":\"0x00000000\",\"prev_block_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000001\",\"block_headers_digest\":\"0x0000000000000000000000000000000000000000000000000000000000000002\",\"transactions_digest\":\"0x0000000000000000000000000000000000000000000000000000000000000003\",\"deposit_digest\":\"0x0000000000000000000000000000000000000000000000000000000000000004\",\"proposed_world_state_digest\":\"0x0000000000000000000000000000000000000000000000000000000000000005\",\"approved_world_state_digest\":\"0x0000000000000000000000000000000000000000000000000000000000000006\",\"latest_account_digest\":\"0x0000000000000000000000000000000000000000000000000000000000000007\"}";
        assert_eq!(encoded_block_header, expected_encoded_block_header);
        let decoded_block_header: BlockHeader<F> =
            serde_json::from_str(expected_encoded_block_header).unwrap();
        assert_eq!(decoded_block_header, block_header);
    }
}
