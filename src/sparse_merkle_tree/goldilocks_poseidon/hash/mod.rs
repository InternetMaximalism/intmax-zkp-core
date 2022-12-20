use std::{fmt::Display, str::FromStr};

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64, Sample},
    },
    hash::hash_types::{HashOut, RichField},
    plonk::config::GenericHashOut,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{SerHexSeq, StrictPfx};

#[cfg(feature = "ecdsa")]
pub mod secp256k1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Wrapper<T>(pub T);

impl<T> std::ops::Deref for Wrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for Wrapper<T> {
    fn from(value: T) -> Self {
        Wrapper(value)
    }
}

pub type WrappedHashOut<F> = Wrapper<HashOut<F>>;
pub type GoldilocksHashOut = WrappedHashOut<GoldilocksField>;

impl<F: Field> Default for WrappedHashOut<F> {
    fn default() -> Self {
        Wrapper(HashOut::ZERO)
    }
}

impl<F: RichField> Display for WrappedHashOut<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for WrappedHashOut<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

#[test]
fn test_fmt_goldilocks_hashout() {
    let value = GoldilocksHashOut::from_u32(1);
    let encoded_value = format!("{}", value);
    assert_eq!(
        encoded_value,
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    let decoded_value = GoldilocksHashOut::from_str("0x01").unwrap();
    assert_eq!(decoded_value, value);

    let value = GoldilocksHashOut::rand();
    let encoded_value = format!("{}", value);
    assert_eq!(encoded_value.len(), 66);
    let decoded_value = GoldilocksHashOut::from_str(&encoded_value).unwrap();
    assert_eq!(decoded_value, value);
}

#[derive(Serialize, Deserialize)]
struct SerializableHashOut(#[serde(with = "SerHexSeq::<StrictPfx>")] pub Vec<u8>);

impl<F: RichField> Serialize for WrappedHashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = self.0.to_bytes(); // little endian
        bytes.reverse(); // big endian
        let raw = SerializableHashOut(bytes);

        raw.serialize(serializer)
    }
}

impl<'de, F: RichField> Deserialize<'de> for WrappedHashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SerializableHashOut::deserialize(deserializer)?;
        let mut bytes = raw.0;
        if bytes.len() > 32 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse(); // little endian
        bytes.resize(32, 0);

        Ok(Wrapper(HashOut::from_bytes(&bytes)))
    }
}

#[test]
fn test_serde_goldilocks_hashout() {
    let value = GoldilocksHashOut::from_u32(1);
    let encoded_value = serde_json::to_string(&value).unwrap();
    assert_eq!(
        encoded_value,
        "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
    );
    let encoded_value = "\"0x01\"";
    let decoded_value: GoldilocksHashOut = serde_json::from_str(encoded_value).unwrap();
    assert_eq!(decoded_value, value);

    let value = GoldilocksHashOut::rand();
    let encoded_value = serde_json::to_string(&value).unwrap();
    assert_eq!(encoded_value.len(), 68); // include 0x-prefix and quotation marks
    let decoded_value: GoldilocksHashOut = serde_json::from_str(&encoded_value).unwrap();
    assert_eq!(decoded_value, value);
}

impl<F: RichField> GenericHashOut<F> for WrappedHashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        HashOut::from_bytes(bytes).into()
    }

    fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}

impl<F: Field> WrappedHashOut<F> {
    pub const ZERO: Self = Wrapper(HashOut::ZERO);

    pub fn read(inputs: &mut core::slice::Iter<F>) -> Self {
        HashOut {
            elements: [
                *inputs.next().unwrap(),
                *inputs.next().unwrap(),
                *inputs.next().unwrap(),
                *inputs.next().unwrap(),
            ],
        }
        .into()
    }

    pub fn write(&self, inputs: &mut Vec<F>) {
        inputs.append(&mut self.0.elements.to_vec())
    }

    pub fn rand() -> Self {
        HashOut::rand().into()
    }
}

impl<F: PrimeField64> WrappedHashOut<F> {
    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ]
    /// ]
    /// ```
    pub fn from_u32(value: u32) -> Self {
        let mut result = HashOut::<F>::default();
        result.elements[0] = F::from_canonical_u32(value);

        Wrapper(result)
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ]
    /// ]
    /// ```
    pub fn to_u32(&self) -> u32 {
        let [l0, l1, l2, l3, _, _, _, _] = self.0.elements[0].to_canonical_u64().to_le_bytes();

        u32::from_le_bytes([l0, l1, l2, l3])
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  4  5  6  7  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ]
    /// ]
    /// ```
    pub fn from_u64(value: u64) -> Self {
        let bytes = value.to_le_bytes();
        let mut result = HashOut::<F>::default();
        for i in 0..2 {
            result.elements[i] = F::from_canonical_u32(u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]));
        }

        Wrapper(result)
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  4  5  6  7  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ],
    ///   [  -  -  -  -  -  -  -  - ]
    /// ]
    /// ```
    pub fn to_u64(&self) -> u64 {
        let [l0, l1, l2, l3, _, _, _, _] = self.0.elements[0].to_canonical_u64().to_le_bytes();
        let [l4, l5, l6, l7, _, _, _, _] = self.0.elements[1].to_canonical_u64().to_le_bytes();

        u64::from_le_bytes([l0, l1, l2, l3, l4, l5, l6, l7])
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  4  5  6  7  -  -  -  - ],
    ///   [  8  9 10 11  -  -  -  - ],
    ///   [ 12 13 14 15  -  -  -  - ]
    /// ]
    /// ```
    pub fn from_u128(value: u128) -> Self {
        let bytes = value.to_le_bytes();
        let mut result = HashOut::<F>::default();
        for i in 0..4 {
            result.elements[i] = F::from_canonical_u32(u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]));
        }

        Wrapper(result)
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  4  5  6  7  -  -  -  - ],
    ///   [  8  9 10 11  -  -  -  - ],
    ///   [ 12 13 14 15  -  -  -  - ]
    /// ]
    /// ```
    pub fn to_u128(&self) -> u128 {
        let [l0, l1, l2, l3, _, _, _, _] = self.0.elements[0].to_canonical_u64().to_le_bytes();
        let [l4, l5, l6, l7, _, _, _, _] = self.0.elements[1].to_canonical_u64().to_le_bytes();
        let [l8, l9, l10, l11, _, _, _, _] = self.0.elements[2].to_canonical_u64().to_le_bytes();
        let [l12, l13, l14, l15, _, _, _, _] = self.0.elements[3].to_canonical_u64().to_le_bytes();

        u128::from_le_bytes([
            l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15,
        ])
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  4  5  6  7  -  -  -  - ],
    ///   [  8  9 10 11  -  -  -  - ],
    ///   [ 12 13 14 15  -  -  -  - ]
    /// ]
    /// ```
    pub fn from_i128(value: i128) -> Self {
        let bytes = value.to_le_bytes();
        let mut result = HashOut::<F>::default();
        for i in 0..4 {
            result.elements[i] = F::from_canonical_u32(u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]));
        }

        Wrapper(result)
    }

    /// ```txt
    /// [
    ///   [  0  1  2  3  -  -  -  - ],
    ///   [  4  5  6  7  -  -  -  - ],
    ///   [  8  9 10 11  -  -  -  - ],
    ///   [ 12 13 14 15  -  -  -  - ]
    /// ]
    /// ```
    pub fn to_i128(&self) -> i128 {
        let value = self.to_u128();

        i128::from_le_bytes(value.to_le_bytes())
    }

    // /// ```txt
    // /// [
    // ///   [  0  1  2  3 16  -  -  - ],
    // ///   [  4  5  6  7 17  -  -  - ],
    // ///   [  8  9 10 11 18  -  -  - ],
    // ///   [ 12 13 14 15 19  -  -  - ]
    // /// ]
    // /// ```
    // pub fn from_address(value: Address) -> Self {
    //     let bytes = value.0;
    //     let mut result = HashOut::<GoldilocksField>::default();
    //     for i in 0..4 {
    //         result.elements[i] = GoldilocksField::from_canonical_u64(u64::from_le_bytes([
    //             bytes[4 * i],
    //             bytes[4 * i + 1],
    //             bytes[4 * i + 2],
    //             bytes[4 * i + 3],
    //             bytes[i + 16],
    //             0,
    //             0,
    //             0,
    //         ]));
    //     }

    //     Wrapper(result)
    // }

    // /// ```txt
    // /// [
    // ///   [  0  1  2  3 16  -  -  - ],
    // ///   [  4  5  6  7 17  -  -  - ],
    // ///   [  8  9 10 11 18  -  -  - ],
    // ///   [ 12 13 14 15 19  -  -  - ]
    // /// ]
    // /// ```
    // pub fn to_address(&self) -> Address {
    //     let [l0, l1, l2, l3, h0, _, _, _] = self.0.elements[0].to_canonical_u64().to_le_bytes();
    //     let [l4, l5, l6, l7, h1, _, _, _] = self.0.elements[1].to_canonical_u64().to_le_bytes();
    //     let [l8, l9, l10, l11, h2, _, _, _] = self.0.elements[2].to_canonical_u64().to_le_bytes();
    //     let [l12, l13, l14, l15, h3, _, _, _] = self.0.elements[3].to_canonical_u64().to_le_bytes();

    //     Address::from([
    //         l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, h0, h1, h2, h3,
    //     ])
    // }
}
