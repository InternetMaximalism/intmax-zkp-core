use num::BigUint;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        secp256k1_base::Secp256K1Base,
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field, PrimeField},
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use plonky2_ecdsa::curve::{
    curve_types::{AffinePoint, Curve},
    ecdsa::{ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};

pub type Address = HashOut<GoldilocksField>;

pub fn private_key_to_public_key<C: Curve>(private_key: ECDSASecretKey<C>) -> ECDSAPublicKey<C> {
    private_key.to_public()
}

pub fn public_key_to_address(public_key: ECDSAPublicKey<Secp256K1>) -> anyhow::Result<Address> {
    let mut left = biguint_to_canonical_field_elements(public_key.0.x.to_canonical_biguint());
    let mut right = biguint_to_canonical_field_elements(public_key.0.y.to_canonical_biguint());
    assert!(left.len() < 5);
    assert!(right.len() < 5);

    left.resize(5, GoldilocksField(0));
    right.resize(5, GoldilocksField(0));

    let inputs = [
        left[0], left[1], left[2], left[3], left[4], right[0], right[1], right[2], right[3],
        right[4],
    ];

    // hash_no_pad(&[...inputs, one, one])
    let hashed_public_key = PoseidonHash::hash_pad(&inputs);

    Ok(hashed_public_key)
}

pub fn biguint_to_canonical_field_elements(value: BigUint) -> Vec<GoldilocksField> {
    let mut elements = vec![];
    let mut value = value;
    while value != BigUint::from(0u8) {
        let e = GoldilocksField::from_noncanonical_biguint(value.clone()); // canonical
        elements.push(e);
        value /= GoldilocksField::order();
    }

    elements
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Account<C: Curve> {
    pub private_key: ECDSASecretKey<C>,
    pub public_key: ECDSAPublicKey<C>,
    pub address: Address,
}

pub fn private_key_to_account(
    private_key: ECDSASecretKey<Secp256K1>,
) -> anyhow::Result<Account<Secp256K1>> {
    let public_key = private_key_to_public_key(private_key);
    let address = public_key_to_address(public_key)?;

    Ok(Account {
        private_key,
        public_key,
        address,
    })
}

#[test]
fn test_sign_message() {
    use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::Sample};
    use plonky2_ecdsa::curve::ecdsa::{sign_message, verify_message};

    let msg = Secp256K1Scalar::rand();
    let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let pk = private_key_to_public_key(sk);
    let sig = sign_message(msg, sk);
    dbg!(sig);
    let is_ok = verify_message(msg, sig, pk);
    assert!(is_ok);
}

// the one-time account is generated using (original private key + nonce) as private key.
pub fn calc_onetime_account<C: Curve>(
    _private_key: ECDSASecretKey<C>,
    _nonce: usize,
) -> anyhow::Result<Account<C>> {
    todo!()
}

// pub fn read_address<R: Read>(reader: &mut R) -> Result<Address, anyhow::Error> {
//     let mut a: [u8; 32] = [0u8; 32];
//     let size = reader.read(&mut a).unwrap();
//     if size != 32 {
//         return Err(anyhow::anyhow!("fail to read address"));
//     }

//     let a = HashOut::from_bytes(&a);

//     Ok(a)
// }

// pub fn write_address<W: Write>(writer: &mut W, address: Address) -> std::io::Result<()> {
//     writer.write_all(&address.to_bytes())?;

//     Ok(())
// }

// #[test]
// fn test_write_address() {
//     let mut writer = vec![];

//     let mut address1 = [0u8; 32];
//     address1[31] = 1;
//     let address1 = HashOut::from_bytes(&address1);
//     write_address(&mut writer, address1).unwrap();

//     let mut address2 = [0u8; 32];
//     address2[31] = 2;
//     let address2 = HashOut::from_bytes(&address2);
//     write_address(&mut writer, address2).unwrap();

//     assert_eq!(format!("{:?}", writer), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]");

//     let reader = &mut std::io::Cursor::new(writer[..48].to_vec());

//     let a = read_address(reader).unwrap();
//     assert_eq!(a, address1);

//     let b = read_address(reader).unwrap();
//     assert_eq!(b, address2);
// }

// Compress scalar to 32 bytes data
pub fn pack_scalar(scalar: Secp256K1Scalar) -> Vec<u8> {
    let mut s = scalar.to_canonical_biguint().to_bytes_be();
    while s.len() < 32 {
        s.push(0);
    }

    s
}

// Decompress scalar from 32 bytes data
pub fn unpack_scalar(packed_scalar: &[u8]) -> Secp256K1Scalar {
    Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(packed_scalar))
}

// Compress affine point to 32 bytes data
pub fn pack_affine_point(affine_point: AffinePoint<Secp256K1>) -> Vec<u8> {
    let mut x = affine_point.x.to_canonical_biguint().to_bytes_be();
    while x.len() < 32 {
        x.push(0);
    }

    let mut y = affine_point.y.to_canonical_biguint().to_bytes_be();
    while y.len() < 32 {
        y.push(0);
    }

    x.append(&mut y);

    x
}

// Decompress affine point from 32 bytes data
pub fn unpack_affine_point(packed_point: &[u8]) -> AffinePoint<Secp256K1> {
    let x = Secp256K1Base::from_noncanonical_biguint(BigUint::from_bytes_be(&packed_point[..32]));

    let y = Secp256K1Base::from_noncanonical_biguint(BigUint::from_bytes_be(&packed_point[32..]));

    AffinePoint::nonzero(x, y)
}

// Compress signature to 64 bytes data
pub fn pack_signature(signature: ECDSASignature<Secp256K1>) -> Vec<u8> {
    let mut r = pack_scalar(signature.r);
    let mut s = pack_scalar(signature.s);
    r.append(&mut s);

    r
}

// Decompress signature from 64 bytes data
pub fn unpack_signature(packed_point: &[u8]) -> ECDSASignature<Secp256K1> {
    let r = unpack_scalar(&packed_point[..32]);
    let s = unpack_scalar(&packed_point[32..]);

    ECDSASignature { r, s }
}
