use num::BigUint;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        secp256k1_base::Secp256K1Base,
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field, PrimeField},
    },
    hash::hash_types::HashOut,
};

impl super::WrappedHashOut<GoldilocksField> {
    pub fn from_noncanonical_secp256k1_scalar(value: Secp256K1Scalar) -> Self {
        let mut elements = [GoldilocksField::ZERO; 4];
        let mut value = value.to_canonical_biguint();
        for e in elements.iter_mut() {
            let _ = std::mem::replace(e, GoldilocksField::from_noncanonical_biguint(value.clone())); // canonical
            value /= GoldilocksField::order();
        }

        HashOut { elements }.into()
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
            let _ = std::mem::replace(e, GoldilocksField::from_noncanonical_biguint(value.clone())); // canonical
            value /= GoldilocksField::order();
        }

        HashOut { elements }.into()
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
