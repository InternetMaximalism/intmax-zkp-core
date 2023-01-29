use std::str::FromStr;

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::hash::WrappedHashOut;

pub type SecretKey<F> = Vec<F>;
pub type PublicKey<F> = HashOut<F>;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Address<F>(pub F);

impl<F: RichField> std::fmt::Display for Address<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for Address<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

// #[derive(Serialize, Deserialize)]
// struct SerializableAddress(#[serde(with = "SerHexSeq::<StrictPfx>")] pub Vec<u8>);

impl<F: RichField> Serialize for Address<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_canonical_u64().to_be_bytes(); // big endian
        let raw = format!("0x{}", hex::encode(bytes));

        raw.serialize(serializer)
    }
}

impl<'de, F: RichField> Deserialize<'de> for Address<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let raw_without_prefix = raw.strip_prefix("0x").ok_or_else(|| {
            serde::de::Error::custom(format!(
                "fail to strip 0x-prefix: given value {raw} does not start with 0x"
            ))
        })?;
        let mut bytes = hex::decode(raw_without_prefix).map_err(|err| {
            serde::de::Error::custom(format!("fail to parse a hex string: {err}"))
        })?;
        if bytes.len() > 8 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse(); // little endian
        bytes.resize(8, 0);

        Ok(Address(F::from_canonical_u64(u64::from_le_bytes(
            bytes.try_into().unwrap(),
        ))))
    }
}

impl<F: Field> std::ops::Deref for Address<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: PrimeField64> Address<F> {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_canonical_u64().to_le_bytes().to_vec()
    }
}

impl<F: Field> Address<F> {
    pub fn to_hash_out(&self) -> HashOut<F> {
        HashOut::from_partial(&[self.0])
    }

    pub fn read(inputs: &mut core::slice::Iter<F>) -> Self {
        Self(*inputs.next().unwrap())
    }

    pub fn write(&self, inputs: &mut Vec<F>) {
        inputs.push(self.0)
    }

    pub fn rand() -> Self {
        Self(F::rand())
    }
}

impl<F: Field> TryFrom<&[F]> for Address<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[F]) -> Result<Self, Self::Error> {
        anyhow::ensure!(elements.len() == 1);
        Ok(Self(elements[0]))
    }
}

pub fn private_key_to_public_key<F: RichField>(private_key: &SecretKey<F>) -> PublicKey<F> {
    PoseidonHash::hash_no_pad(private_key)
}

pub fn public_key_to_address<F: RichField>(public_key: PublicKey<F>) -> Address<F> {
    Address(public_key.elements[0])
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Account<F: RichField> {
    pub private_key: SecretKey<F>,
    pub public_key: PublicKey<F>,
    pub address: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableAccount {
    pub private_key: Vec<GoldilocksField>,
    pub public_key: WrappedHashOut<GoldilocksField>,
    pub address: Address<GoldilocksField>,
}

impl From<SerializableAccount> for Account<GoldilocksField> {
    fn from(value: SerializableAccount) -> Self {
        Self {
            private_key: value.private_key,
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
            private_key: value.private_key,
            public_key: value.public_key.into(),
            address: value.address,
        }
    }
}

impl Serialize for Account<GoldilocksField> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = SerializableAccount::from(self.clone());

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
    let public_key = private_key_to_public_key(&private_key);
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
        let private_key = F::rand_vec(4);

        Account::new(private_key)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use plonky2::field::goldilocks_field::GoldilocksField;

    use crate::zkdsa::account::Address;

    #[test]
    fn test_fmt_address() {
        let value = Address(GoldilocksField(1));
        let encoded_value = format!("{}", value);
        assert_eq!(encoded_value, "0x0000000000000001");
        let decoded_value: Address<GoldilocksField> = Address::from_str("0x01").unwrap();
        assert_eq!(decoded_value, value);

        let value: Address<GoldilocksField> = Address::rand();
        let encoded_value = format!("{}", value);
        assert_eq!(encoded_value.len(), 18);
        let decoded_value = Address::from_str(&encoded_value).unwrap();
        assert_eq!(decoded_value, value);
    }

    #[test]
    fn test_serialize_address() {
        use plonky2::field::goldilocks_field::GoldilocksField;

        let value = Address(GoldilocksField(1));
        let encoded_value = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded_value, "\"0x0000000000000001\"");
        let encoded_value = "\"0x01\"";
        let decoded_value: Address<GoldilocksField> = serde_json::from_str(encoded_value).unwrap();
        assert_eq!(decoded_value, value);

        let value: Address<GoldilocksField> = Address::rand();
        let encoded_value = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded_value.len(), 20); // include 0x-prefix and quotation marks
        let decoded_value: Address<GoldilocksField> = serde_json::from_str(&encoded_value).unwrap();
        assert_eq!(decoded_value, value);
    }

    #[test]
    fn test_address_from_vec() {
        let flat_address = [GoldilocksField(12487169361498783628)];
        let new_address: Address<GoldilocksField> = Address::try_from(&flat_address[..]).unwrap();
        assert_eq!(new_address, Address(GoldilocksField(12487169361498783628)));
    }
}
