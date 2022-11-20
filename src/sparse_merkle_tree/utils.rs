use std::{fmt::Debug, ops::Deref};

use hex::{FromHex, ToHex};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use serde_hex::{SerHex, SerHexOpt, SerHexSeq, StrictPfx};
// use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// pub trait ToHex {
//     /// Encode the hex string representing `self` into the result. Lower case
//     /// letters are used (e.g. `f9b4ca`)
//     fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T;

//     /// Encode the hex string representing `self` into the result. Upper case
//     /// letters are used (e.g. `F9B4CA`)
//     fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T;
// }

// pub trait ToHex {
//     fn encode_hex(&self) -> String;
// }

// pub trait FromHex: Sized {
//     type Error;

//     /// Creates an instance of type `Self` from the given hex string, or fails
//     /// with a custom error type.
//     ///
//     /// Both, upper and lower case characters are valid and can even be
//     /// mixed (e.g. `f9b4ca`, `F9B4CA` and `f9B4Ca` are all valid strings).
//     fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error>;
// }

// pub trait FromHex: Sized {
//     type Error: 'static + Debug + Sync + Send;

//     fn from_hex(hex: &str) -> Result<Self, Self::Error>;
// }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HexableValue<V>(pub V);

impl<V: Into<Vec<u8>> + From<Vec<u8>>> From<V> for HexableValue<V> {
    fn from(value: V) -> Self {
        Self(value)
    }
}

impl<V: Into<Vec<u8>> + From<Vec<u8>>> HexableValue<V> {
    pub fn unwrap(self) -> V {
        self.0
    }
}

impl<V: Into<Vec<u8>> + From<Vec<u8>>> Deref for HexableValue<V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V: Into<Vec<u8>> + From<Vec<u8>>> AsRef<V> for HexableValue<V> {
    fn as_ref(&self) -> &V {
        self.deref()
    }
}

// impl<V: Into<Vec<u8>> + From<Vec<u8>>> Serialize for HexableValue<V> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         // let new_self = String::from("0x") + &hex::encode(&write_field_element_be(&self.0));
//         let new_self = self.0.to_bytes_be();
//         let new_self = String::from("0x") + &hex::encode(new_self);

//         new_self.serialize(serializer)
//     }
// }

// impl<'de, V: Into<Vec<u8>> + From<Vec<u8>>> Deserialize<'de> for HexableValue<V> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let raw_result = String::deserialize(deserializer)?;

//         let result = hex::decode(&raw_result[2..]).unwrap();
//         let result = Self(V::from_bytes_be(result).expect("fail to read field element"));

//         Ok(result)
//     }
// }

// impl AsRef<[u8]> for HexableValue<HashOut<GoldilocksField>> {
//     fn as_ref(&self) -> &[u8] {
//         self.0.to_bytes().as_ref()
//     }
// }

impl ToHex for &HexableValue<HashOut<GoldilocksField>> {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        todo!()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        todo!()
    }
}

impl FromHex for HexableValue<HashOut<GoldilocksField>> {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        todo!()
    }
}

// impl AsRef<[u8]> for &HexableValue<u32> {
//     fn as_ref(&self) -> &[u8] {}
// }

impl ToHex for &HexableValue<u32> {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        todo!()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        todo!()
    }
}

impl FromHex for HexableValue<u32> {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let a: [u8; 4] = hex.as_ref().try_into().unwrap();

        Ok(HexableValue(u32::from_be_bytes(a)))
    }
}

impl ToHex for &HexableValue<u64> {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        todo!()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        todo!()
    }
}

impl FromHex for HexableValue<u64> {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let a: [u8; 8] = hex.as_ref().try_into().unwrap();

        Ok(HexableValue(u64::from_be_bytes(a)))
    }
}
