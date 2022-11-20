use std::{fmt::Display, str::FromStr};

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    },
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::{GenericHashOut, Hasher},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{SerHexSeq, StrictPfx};

use crate::sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut;

pub type SecretKey<F> = HashOut<F>;
pub type PublicKey<F> = HashOut<F>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Address<F: Field>(pub HashOut<F>);

#[derive(Serialize, Deserialize)]
pub struct SerializableAddress(#[serde(with = "SerHexSeq::<StrictPfx>")] pub Vec<u8>);

impl<F: RichField> Display for Address<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = self.0.to_bytes(); // little endian
        bytes.reverse(); // big endian

        write!(f, "{}", hex::encode(&bytes))
    }
}

impl<F: RichField> FromStr for Address<F> {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut raw = hex::decode(&s)?;
        raw.reverse();
        raw.resize(32, 0);

        Ok(Address(HashOut::from_bytes(&raw)))
    }
}

#[test]
fn test_fmt_address() {
    use crate::sparse_merkle_tree::goldilocks_poseidon::GoldilocksHashOut;

    let value = Address(*GoldilocksHashOut::from_u32(1));
    let encoded_value = format!("{}", value);
    assert_eq!(
        encoded_value,
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    let decoded_value: Address<GoldilocksField> = Address::from_str("01").unwrap();
    assert_eq!(decoded_value, value);

    let value: Address<GoldilocksField> = Address::rand();
    let encoded_value = format!("{}", value);
    assert_eq!(encoded_value.len(), 64);
    let decoded_value = Address::from_str(&encoded_value).unwrap();
    assert_eq!(decoded_value, value);
}

impl<F: RichField> Serialize for Address<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw = format!("0x{}", self);

        serializer.serialize_str(&raw)
    }
}

impl<'de, F: RichField> Deserialize<'de> for Address<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;

        Ok(Address::from_str(&raw[2..]).unwrap())
    }
}

#[test]
fn test_serialize_address() {
    use crate::sparse_merkle_tree::goldilocks_poseidon::GoldilocksHashOut;
    use plonky2::field::goldilocks_field::GoldilocksField;

    let value = Address(*GoldilocksHashOut::from_u32(1));
    let encoded_value = serde_json::to_string(&value).unwrap();
    assert_eq!(
        encoded_value,
        "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
    );
    let decoded_value: Address<GoldilocksField> = serde_json::from_str("\"0x01\"").unwrap();
    assert_eq!(decoded_value, value);

    let value: Address<GoldilocksField> = Address::rand();
    let encoded_value = serde_json::to_string(&value).unwrap();
    assert_eq!(encoded_value.len(), 68); // include 0x-prefix and quotation marks
    let decoded_value: Address<GoldilocksField> = serde_json::from_str(&encoded_value).unwrap();
    assert_eq!(decoded_value, value);
}

impl<F: Field> std::ops::Deref for Address<F> {
    type Target = HashOut<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Field + Sample> Address<F> {
    pub fn to_hash_out(&self) -> HashOut<F> {
        self.0
    }

    pub fn read(inputs: &mut core::slice::Iter<F>) -> Self {
        Self(HashOut {
            elements: [
                *inputs.next().unwrap(),
                *inputs.next().unwrap(),
                *inputs.next().unwrap(),
                *inputs.next().unwrap(),
            ],
        })
    }

    pub fn write(&self, inputs: &mut Vec<F>) {
        inputs.append(&mut self.0.elements.to_vec())
    }

    pub fn rand() -> Self {
        Self(HashOut::rand())
    }
}

pub fn private_key_to_public_key<F: RichField>(private_key: SecretKey<F>) -> PublicKey<F> {
    PoseidonHash::two_to_one(private_key, private_key)
}

pub fn public_key_to_address<F: RichField>(public_key: PublicKey<F>) -> Address<F> {
    Address(public_key)
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Account<F: RichField> {
    pub private_key: SecretKey<F>,
    pub public_key: PublicKey<F>,
    pub address: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableAccount {
    pub private_key: WrappedHashOut<GoldilocksField>,
    pub public_key: WrappedHashOut<GoldilocksField>,
    pub address: Address<GoldilocksField>,
}

impl From<SerializableAccount> for Account<GoldilocksField> {
    fn from(value: SerializableAccount) -> Self {
        Self {
            private_key: *value.private_key,
            public_key: *value.public_key,
            address: value.address,
        }
    }
}

impl<'de> Deserialize<'de> for Account<GoldilocksField> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = SerializableAccount::deserialize(deserializer)?;

        Ok(raw.into())
    }
}

impl From<Account<GoldilocksField>> for SerializableAccount {
    fn from(value: Account<GoldilocksField>) -> Self {
        Self {
            private_key: value.private_key.into(),
            public_key: value.public_key.into(),
            address: value.address,
        }
    }
}

impl Serialize for Account<GoldilocksField> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = SerializableAccount::from(*self);

        raw.serialize(serializer)
    }
}

#[test]
fn test_serde_account() {
    let account: Account<GoldilocksField> = Account::rand();
    let encoded_account = serde_json::to_string(&account).unwrap();
    let decoded_account: Account<GoldilocksField> = serde_json::from_str(&encoded_account).unwrap();
    assert_eq!(decoded_account, account);
}

pub fn private_key_to_account<F: RichField>(private_key: SecretKey<F>) -> Account<F> {
    let public_key = private_key_to_public_key(private_key);
    let address = public_key_to_address(public_key);

    Account {
        private_key,
        public_key,
        address,
    }
}

impl<F: RichField> Account<F> {
    pub fn new(private_key: SecretKey<F>) -> Self {
        private_key_to_account(private_key)
    }

    pub fn rand() -> Self {
        let private_key = HashOut::rand();

        Account::new(private_key)
    }
}
