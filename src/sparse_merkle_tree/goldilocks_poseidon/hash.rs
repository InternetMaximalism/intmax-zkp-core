use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Display, str::FromStr};
use num::BigUint;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        secp256k1_base::Secp256K1Base,
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field, PrimeField, PrimeField64, Sample},
    },
    hash::hash_types::{HashOut, RichField},
    plonk::config::GenericHashOut,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Wrapper<T>(pub T);

impl<T> core::ops::Deref for Wrapper<T> {
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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut bytes = self.0.to_bytes(); // little endian
        bytes.reverse(); // big endian

        write!(f, "{}", hex::encode(&bytes))
    }
}

impl<F: RichField> FromStr for WrappedHashOut<F> {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut raw = hex::decode(&s)?;
        raw.reverse();
        raw.resize(32, 0);

        Ok(Wrapper(HashOut::from_bytes(&raw)))
    }
}

#[test]
fn test_fmt_goldilocks_hashout() {
    let value = GoldilocksHashOut::from_u32(1);
    let encoded_value = format!("{}", value);
    assert_eq!(
        encoded_value,
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    let decoded_value = GoldilocksHashOut::from_str("01").unwrap();
    assert_eq!(decoded_value, value);

    let value = GoldilocksHashOut::rand();
    let encoded_value = format!("{}", value);
    assert_eq!(encoded_value.len(), 64);
    let decoded_value = GoldilocksHashOut::from_str(&encoded_value).unwrap();
    assert_eq!(decoded_value, value);
}

impl<F: RichField> Serialize for WrappedHashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw = "0x".to_string() + &self.to_string();

        serializer.serialize_str(&raw)
    }
}

impl<'de, F: RichField> Deserialize<'de> for WrappedHashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;

        Ok(WrappedHashOut::from_str(&raw[2..]).unwrap())
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
    let decoded_value: GoldilocksHashOut = serde_json::from_str("\"0x01\"").unwrap();
    assert_eq!(decoded_value, value);

    let value = GoldilocksHashOut::rand();
    let encoded_value = serde_json::to_string(&value).unwrap();
    assert_eq!(encoded_value.len(), 68); // include 0x-prefix and quotation marks
    let decoded_value: GoldilocksHashOut = serde_json::from_str(&encoded_value).unwrap();
    assert_eq!(decoded_value, value);
}

impl<F: RichField> WrappedHashOut<F> {
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

impl<F: RichField> PartialOrd for WrappedHashOut<F> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.to_bytes().partial_cmp(&other.0.to_bytes())
    }
}

impl<F: RichField> Ord for WrappedHashOut<F> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
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

impl WrappedHashOut<GoldilocksField> {
    pub fn from_noncanonical_secp256k1_scalar(value: Secp256K1Scalar) -> Self {
        let mut elements = [GoldilocksField::ZERO; 4];
        let mut value = value.to_canonical_biguint();
        for e in elements.iter_mut() {
            let _ =
                core::mem::replace(e, GoldilocksField::from_noncanonical_biguint(value.clone())); // canonical
            value /= GoldilocksField::order();
        }

        Wrapper(HashOut { elements })
    }

    pub fn to_canonical_secp256k1_scalar(&self) -> Secp256K1Scalar {
        let mut result = BigUint::from(0u64);
        let mut power = BigUint::from(1u64);
        for e in self.0.elements {
            result += e.to_canonical_biguint() * &power;
            power *= GoldilocksField::order();
        }

        Secp256K1Scalar::from_noncanonical_biguint(result) // canonical
    }

    pub fn from_noncanonical_secp256k1_base(value: Secp256K1Base) -> Self {
        let mut elements = [GoldilocksField::ZERO; 4];
        let mut value = value.to_canonical_biguint();
        for e in elements.iter_mut() {
            let _ =
                core::mem::replace(e, GoldilocksField::from_noncanonical_biguint(value.clone())); // canonical
            value /= GoldilocksField::order();
        }

        Wrapper(HashOut { elements })
    }

    pub fn to_canonical_secp256k1_base(&self) -> Secp256K1Base {
        let mut result = BigUint::from(0u64);
        let mut power = BigUint::from(1u64);
        for e in self.0.elements {
            result += e.to_canonical_biguint() * &power;
            power *= GoldilocksField::order();
        }

        Secp256K1Base::from_noncanonical_biguint(result) // canonical
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            secp256k1_base::Secp256K1Base,
            secp256k1_scalar::Secp256K1Scalar,
            types::{Field, Sample},
        },
        hash::hash_types::HashOut,
    };

    use crate::sparse_merkle_tree::goldilocks_poseidon::{GoldilocksHashOut, Wrapper};

    #[test]
    fn test_to_scalar_is_always_canonical() {
        let random = Wrapper(HashOut::<GoldilocksField>::rand());
        let a = random.to_canonical_secp256k1_scalar();
        let b = GoldilocksHashOut::from_noncanonical_secp256k1_scalar(a);
        assert_eq!(b, random);
    }

    #[test]
    fn test_from_scalar_may_be_noncanonical() {
        let random = Secp256K1Scalar::NEG_ONE;
        let a = GoldilocksHashOut::from_noncanonical_secp256k1_scalar(random);
        let b = a.to_canonical_secp256k1_scalar();
        assert_ne!(b, random);
    }

    #[test]
    fn test_to_base_is_always_canonical() {
        let random = Wrapper(HashOut::<GoldilocksField>::rand());
        let a = random.to_canonical_secp256k1_base();
        let b = GoldilocksHashOut::from_noncanonical_secp256k1_base(a);
        assert_eq!(b, random);
    }

    #[test]
    fn test_from_base_may_be_noncanonical() {
        let random = Secp256K1Base::NEG_ONE;
        let a = GoldilocksHashOut::from_noncanonical_secp256k1_base(random);
        let b = a.to_canonical_secp256k1_base();
        assert_ne!(b, random);
    }
}
