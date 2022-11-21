use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::{
    sparse_merkle_tree::{
        gadgets::verify::verify_smt::SmtInclusionProof, goldilocks_poseidon::WrappedHashOut,
    },
    transaction::block_header::BlockHeader,
    zkdsa::account::Address,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenKind<F: RichField> {
    #[serde(bound(
        serialize = "Address<F>: Serialize",
        deserialize = "Address<F>: Deserialize<'de>"
    ))]
    pub contract_address: Address<F>,
    #[serde(bound(
        serialize = "WrappedHashOut<F>: Serialize",
        deserialize = "WrappedHashOut<F>: Deserialize<'de>"
    ))]
    pub variable_index: WrappedHashOut<F>,
}

#[test]
fn test_serde_token_kind() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Sample},
        hash::hash_types::HashOut,
    };

    let kind: TokenKind<GoldilocksField> = TokenKind {
        contract_address: Address::rand(),
        variable_index: HashOut::rand().into(),
    };
    let encoded_kind = serde_json::to_string(&kind).unwrap();
    let decoded_kind: TokenKind<GoldilocksField> = serde_json::from_str(&encoded_kind).unwrap();
    assert_eq!(decoded_kind, kind);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset<F: RichField> {
    #[serde(bound(
        serialize = "TokenKind<F>: Serialize",
        deserialize = "TokenKind<F>: Deserialize<'de>"
    ))]
    pub kind: TokenKind<F>,
    pub amount: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "BlockHeader<F>: Serialize, SmtInclusionProof<F>: Serialize, Asset<F>: Serialize",
    deserialize = "BlockHeader<F>: Deserialize<'de>, SmtInclusionProof<F>: Deserialize<'de>, Asset<F>: Deserialize<'de>"
))]
pub struct ReceivedAssetProof<F: RichField> {
    pub is_deposit: bool,
    pub diff_tree_inclusion_proof: (BlockHeader<F>, SmtInclusionProof<F>, SmtInclusionProof<F>),
    pub account_tree_inclusion_proof: SmtInclusionProof<F>,
    pub asset: Asset<F>,
}
