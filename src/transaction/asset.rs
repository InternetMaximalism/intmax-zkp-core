use core::str::FromStr;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::tree::MerkleProof,
    rollup::gadgets::deposit_block::{DepositInfo, VariableIndex},
    sparse_merkle_tree::{
        gadgets::verify::verify_smt::SmtInclusionProof, goldilocks_poseidon::WrappedHashOut,
    },
    transaction::block_header::BlockHeader,
    zkdsa::account::Address,
};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenKind<F: RichField> {
    #[serde(bound(
        serialize = "Address<F>: Serialize",
        deserialize = "Address<F>: Deserialize<'de>"
    ))]
    pub contract_address: Address<F>,
    #[serde(bound(
        serialize = "VariableIndex<F>: Serialize",
        deserialize = "VariableIndex<F>: Deserialize<'de>"
    ))]
    pub variable_index: VariableIndex<F>,
}

#[test]
fn test_serde_token_kind() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Sample},
        hash::hash_types::HashOut,
    };

    let kind: TokenKind<GoldilocksField> = TokenKind {
        contract_address: Address::rand(),
        variable_index: VariableIndex::from_hash_out(HashOut::<GoldilocksField>::rand()),
    };
    let encoded_kind = serde_json::to_string(&kind).unwrap();
    let decoded_kind: TokenKind<GoldilocksField> = serde_json::from_str(&encoded_kind).unwrap();
    assert_eq!(decoded_kind, kind);
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset<F: RichField> {
    #[serde(bound(
        serialize = "TokenKind<F>: Serialize",
        deserialize = "TokenKind<F>: Deserialize<'de>"
    ))]
    pub kind: TokenKind<F>,
    pub amount: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributedAsset<F: RichField> {
    #[serde(bound(
        serialize = "Address<F>: Serialize",
        deserialize = "Address<F>: Deserialize<'de>"
    ))]
    pub receiver_address: Address<F>,
    #[serde(flatten)]
    #[serde(bound(
        serialize = "TokenKind<F>: Serialize",
        deserialize = "TokenKind<F>: Deserialize<'de>"
    ))]
    pub kind: TokenKind<F>,
    pub amount: u64,
}

impl<F: RichField> FromStr for ContributedAsset<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl<F: RichField> core::fmt::Display for ContributedAsset<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> From<ContributedAsset<F>> for DepositInfo<F> {
    fn from(value: ContributedAsset<F>) -> Self {
        Self {
            receiver_address: value.receiver_address,
            contract_address: value.kind.contract_address,
            variable_index: value.kind.variable_index,
            amount: F::from_canonical_u64(value.amount),
        }
    }
}

impl<F: RichField> From<DepositInfo<F>> for ContributedAsset<F> {
    fn from(value: DepositInfo<F>) -> Self {
        Self {
            receiver_address: value.receiver_address,
            kind: TokenKind {
                contract_address: value.contract_address,
                variable_index: value.variable_index,
            },
            amount: value.amount.to_canonical_u64(),
        }
    }
}

#[test]
fn test_serde_owned_asset() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    let owned_asset: ContributedAsset<GoldilocksField> = ContributedAsset {
        receiver_address: Address::rand(),
        kind: TokenKind {
            contract_address: Address::rand(),
            variable_index: 1u8.into(),
        },
        amount: 10,
    };

    let encoded_owned_asset = serde_json::to_string(&owned_asset).unwrap();
    let decoded_owned_asset: ContributedAsset<GoldilocksField> =
        serde_json::from_str(&encoded_owned_asset).unwrap();
    assert_eq!(decoded_owned_asset, owned_asset);

    // ContributedAsset は DepositInfo と互換性がある.
    let decoded_deposit_info: DepositInfo<GoldilocksField> =
        serde_json::from_str(&encoded_owned_asset).unwrap();
    assert_eq!(decoded_deposit_info, owned_asset.into());

    let encoded_owned_asset = owned_asset.to_string();
    dbg!(&encoded_owned_asset);
    let decoded_owned_asset: ContributedAsset<GoldilocksField> =
        ContributedAsset::from_str(&encoded_owned_asset).unwrap();
    assert_eq!(decoded_owned_asset, owned_asset);
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "BlockHeader<F>: Serialize, SmtInclusionProof<F>: Serialize, Asset<F>: Serialize",
    deserialize = "BlockHeader<F>: Deserialize<'de>, SmtInclusionProof<F>: Deserialize<'de>, Asset<F>: Deserialize<'de>"
))]
pub struct ReceivedAssetProof<F: RichField> {
    pub is_deposit: bool,
    pub diff_tree_inclusion_proof: (BlockHeader<F>, MerkleProof<F>, SmtInclusionProof<F>),
    pub latest_account_tree_inclusion_proof: SmtInclusionProof<F>,
    pub assets: Vec<Asset<F>>,
    pub nonce: WrappedHashOut<F>,
}
