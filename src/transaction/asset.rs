use core::str::FromStr;
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::tree::MerkleProof,
    // sparse_merkle_tree::gadgets::verify::verify_smt::SmtInclusionProof,
    transaction::{block_header::BlockHeader, gadgets::deposit_info::DepositInfo},
    utils::hash::WrappedHashOut,
    zkdsa::account::Address,
};

use super::tree::tx_diff::TransactionWithNullifier;

/// `TokenKind` で、トークンの種類を記述するのに使われる構造体
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VariableIndex<F>(pub u32, core::marker::PhantomData<F>);

impl<F: Field> From<u8> for VariableIndex<F> {
    fn from(value: u8) -> Self {
        Self(value as u32, core::marker::PhantomData)
    }
}

impl<F: Field> From<u32> for VariableIndex<F> {
    fn from(value: u32) -> Self {
        Self(value, core::marker::PhantomData)
    }
}

impl<F: RichField> VariableIndex<F> {
    pub fn to_hash_out(&self) -> HashOut<F> {
        HashOut::from_partial(&[F::from_canonical_u32(self.0)])
    }

    pub fn from_hash_out(value: HashOut<F>) -> Self {
        Self::read(&mut value.elements.iter())
    }

    pub fn read(inputs: &mut core::slice::Iter<F>) -> Self {
        let value = WrappedHashOut::read(inputs).0.elements[0].to_canonical_u64() as u32;

        value.into()
    }

    pub fn write(&self, inputs: &mut Vec<F>) {
        inputs.append(&mut self.to_hash_out().elements.to_vec());
    }
}

impl<F: RichField> TryFrom<&[F]> for VariableIndex<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[F]) -> Result<Self, Self::Error> {
        anyhow::ensure!(elements.len() == 4);

        Ok(Self::read(&mut elements.to_vec().iter()))
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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset<F> {
    #[serde(bound = "F: RichField")]
    pub kind: TokenKind<F>,
    pub amount: u64,
}

impl<F: RichField> Asset<F> {
    pub fn encode(&self) -> Vec<F> {
        let mut result = vec![];
        self.kind.contract_address.write(&mut result);
        self.kind.variable_index.write(&mut result);
        result.push(F::from_canonical_u64(self.amount));

        result
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct Transaction<F: RichField> {
    pub to: Address<F>,
    #[serde(flatten)]
    pub kind: TokenKind<F>,
    pub amount: u64,
}

impl<F: RichField> Transaction<F> {
    pub fn encode(&self) -> Vec<F> {
        let mut result = vec![];
        self.to.write(&mut result);
        self.kind.contract_address.write(&mut result);
        self.kind.variable_index.write(&mut result);
        result.push(F::from_canonical_u64(self.amount));

        result
    }
}

impl<F: RichField> FromStr for Transaction<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl<F: RichField> core::fmt::Display for Transaction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> From<Transaction<F>> for DepositInfo<F> {
    fn from(value: Transaction<F>) -> Self {
        Self {
            receiver_address: value.to,
            contract_address: value.kind.contract_address,
            variable_index: value.kind.variable_index,
            amount: F::from_canonical_u64(value.amount),
        }
    }
}

impl<F: RichField> From<DepositInfo<F>> for Transaction<F> {
    fn from(value: DepositInfo<F>) -> Self {
        Self {
            to: value.receiver_address,
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
        let bytes = self.0.to_be_bytes();
        let raw = format!("0x{}", hex::encode(bytes));

        raw.serialize(serializer)
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
        let mut bytes = hex::decode(raw_without_prefix).map_err(|err| {
            serde::de::Error::custom(format!("fail to parse a hex string: {err}"))
        })?;
        if bytes.len() > 4 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse(); // little endian
        bytes.resize(4, 0);

        let raw = u32::from_le_bytes(bytes.try_into().map_err(|_| {
            serde::de::Error::custom(format!("out of index: given value {raw} is too short"))
        })?);

        Ok(raw.into())
    }
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct ReceivedAssetProof<F: RichField, H: Hasher<F>> {
    pub is_deposit: bool,
    pub diff_tree_inclusion_proof: (
        BlockHeader<F>,
        MerkleProof<F, H, usize, TransactionWithNullifier<F, H>>,
    ),
    pub latest_account_tree_inclusion_proof: MerkleProof<F, H, usize, H::Hash>,
    pub assets: Vec<Asset<F>>,
    pub nonce: H::Hash,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct TokenKind<F> {
    pub contract_address: Address<F>,
    pub variable_index: VariableIndex<F>,
}

#[cfg(test)]
mod tests {
    use crate::{
        transaction::asset::{Asset, FromStr, TokenKind, Transaction, VariableIndex},
        zkdsa::account::Address,
    };

    #[test]
    fn test_fmt_variable_index() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let value = VariableIndex::from(20u8);
        let encoded_value = format!("{}", value);
        assert_eq!(encoded_value, "0x00000014");
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
    fn test_variable_index_from_vec() {
        use plonky2::{
            field::{goldilocks_field::GoldilocksField, types::Sample},
            hash::hash_types::HashOut,
        };

        let variable_index = VariableIndex::from_hash_out(HashOut::<GoldilocksField>::rand());
        let flat_variable_index = variable_index.to_hash_out().elements.to_vec();
        let new_variable_index: VariableIndex<GoldilocksField> =
            VariableIndex::try_from(&flat_variable_index[..]).unwrap();
        assert_eq!(new_variable_index, variable_index);
    }

    #[test]
    fn test_serde_owned_asset() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let owned_asset: Transaction<GoldilocksField> = Transaction {
            to: Address::rand(),
            kind: TokenKind {
                contract_address: Address::rand(),
                variable_index: 1u8.into(),
            },
            amount: 10,
        };

        let encoded_owned_asset = serde_json::to_string(&owned_asset).unwrap();
        let decoded_owned_asset: Transaction<GoldilocksField> =
            serde_json::from_str(&encoded_owned_asset).unwrap();
        assert_eq!(decoded_owned_asset, owned_asset);

        let encoded_owned_asset = owned_asset.to_string();
        dbg!(&encoded_owned_asset);
        let decoded_owned_asset: Transaction<GoldilocksField> =
            Transaction::from_str(&encoded_owned_asset).unwrap();
        assert_eq!(decoded_owned_asset, owned_asset);
    }

    #[test]
    fn test_encode_asset() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let asset = Asset {
            kind: TokenKind {
                contract_address: Address(GoldilocksField(5286999446705332053u64)),
                variable_index: 320841071u32.into(),
            },
            amount: 1003380560037325279,
        };
        let encoded_asset = asset.encode();
        let expected_vec = vec![
            GoldilocksField(5286999446705332053),
            GoldilocksField(320841071),
            GoldilocksField(0),
            GoldilocksField(0),
            GoldilocksField(0),
            GoldilocksField(1003380560037325279),
        ];
        assert_eq!(encoded_asset, expected_vec);
    }

    #[test]
    fn test_encode_transaction() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let transaction = Transaction {
            to: Address(GoldilocksField(17953406509064499258)),
            kind: TokenKind {
                contract_address: Address(GoldilocksField(5286999446705332053u64)),
                variable_index: 320841071u32.into(),
            },
            amount: 1003380560037325279,
        };
        let encoded_transaction = transaction.encode();
        let expected_vec = vec![
            GoldilocksField(17953406509064499258),
            GoldilocksField(5286999446705332053),
            GoldilocksField(320841071),
            GoldilocksField(0),
            GoldilocksField(0),
            GoldilocksField(0),
            GoldilocksField(1003380560037325279),
        ];
        assert_eq!(encoded_transaction, expected_vec);
    }
}
