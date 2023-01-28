use core::str::FromStr;
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::tree::MerkleProof,
    sparse_merkle_tree::gadgets::verify::verify_smt::SmtInclusionProof,
    transaction::{block_header::BlockHeader, gadgets::deposit_info::DepositInfo},
    utils::hash::WrappedHashOut,
    zkdsa::account::Address,
};

/// `TokenKind` で、トークンの種類を記述するのに使われる構造体
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VariableIndex<F>(pub u8, core::marker::PhantomData<F>);

impl<F: Field> From<u8> for VariableIndex<F> {
    fn from(value: u8) -> Self {
        Self(value, core::marker::PhantomData)
    }
}

impl<F: RichField> VariableIndex<F> {
    pub fn to_hash_out(&self) -> HashOut<F> {
        HashOut::from_partial(&[F::from_canonical_u8(self.0)])
    }

    pub fn from_hash_out(value: HashOut<F>) -> Self {
        Self::read(&mut value.elements.iter())
    }

    pub fn read(inputs: &mut core::slice::Iter<F>) -> Self {
        let value = WrappedHashOut::read(inputs).0.elements[0].to_canonical_u64() as u8;

        value.into()
    }

    pub fn write(&self, inputs: &mut Vec<F>) {
        inputs.append(&mut self.to_hash_out().elements.to_vec());
    }
}

impl<F: RichField> std::fmt::Display for VariableIndex<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for VariableIndex<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

impl<'de, F: RichField> Deserialize<'de> for VariableIndex<F> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let raw_without_prefix = raw.strip_prefix("0x").ok_or_else(|| {
            serde::de::Error::custom(format!(
                "fail to strip 0x-prefix: given value {raw} does not start with 0x"
            ))
        })?;
        let bytes = hex::decode(raw_without_prefix).map_err(|err| {
            serde::de::Error::custom(format!("fail to parse a hex string: {err}"))
        })?;
        let raw = *bytes.first().ok_or_else(|| {
            serde::de::Error::custom(format!("out of index: given value {raw} is too short"))
        })?;

        Ok(raw.into())
    }
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

impl<F: RichField> Asset<F> {
    pub fn encode(&self) -> Vec<F> {
        [
            self.kind.contract_address.0.elements.to_vec(),
            self.kind.variable_index.to_hash_out().elements.to_vec(),
            vec![F::from_canonical_u64(self.amount)],
        ]
        .concat()
    }
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

impl<F: RichField> ContributedAsset<F> {
    pub fn encode(&self) -> Vec<F> {
        [
            self.receiver_address.0.elements.to_vec(),
            self.kind.contract_address.0.elements.to_vec(),
            self.kind.variable_index.to_hash_out().elements.to_vec(),
            vec![F::from_canonical_u64(self.amount)],
        ]
        .concat()
    }
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

impl<F: RichField> Serialize for VariableIndex<F> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = [self.0];
        let raw = format!("0x{}", hex::encode(bytes));

        raw.serialize(serializer)
    }
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "BlockHeader<F>: Serialize, SmtInclusionProof<F>: Serialize, Asset<F>: Serialize",
    deserialize = "BlockHeader<F>: Deserialize<'de>, SmtInclusionProof<F>: Deserialize<'de>, Asset<F>: Deserialize<'de>"
))]
pub struct ReceivedAssetProof<F: RichField, H: Hasher<F>> {
    pub is_deposit: bool,
    pub diff_tree_inclusion_proof: (
        BlockHeader<F>,
        MerkleProof<F, H, usize>,
        SmtInclusionProof<F>,
    ),
    pub latest_account_tree_inclusion_proof: SmtInclusionProof<F>,
    pub assets: Vec<Asset<F>>,
    pub nonce: H::Hash,
}

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

#[cfg(test)]
mod tests {

    use crate::transaction::asset::ContributedAsset;
    use crate::transaction::asset::FromStr;
    use crate::transaction::asset::TokenKind;
    use crate::transaction::asset::VariableIndex;
    use crate::transaction::gadgets::deposit_info::DepositInfo;
    use crate::zkdsa::account::Address;

    #[test]
    fn test_fmt_variable_index() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let value = VariableIndex::from(20u8);
        let encoded_value = format!("{}", value);
        assert_eq!(encoded_value, "0x14");
        let decoded_value: VariableIndex<GoldilocksField> =
            VariableIndex::from_str("0x14").unwrap();
        assert_eq!(decoded_value, value);
    }

    #[test]
    fn test_serde_variable_index() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let value: VariableIndex<GoldilocksField> = 20u8.into();
        let encoded = serde_json::to_string(&value).unwrap();
        let decoded: VariableIndex<GoldilocksField> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, value);
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
}
