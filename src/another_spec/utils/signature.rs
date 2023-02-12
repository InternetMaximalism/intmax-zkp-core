use anyhow::anyhow;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};

use crate::newspec::common::account::{AddressTarget, PublicKey};
use bls_signatures_rs::{bn256::Bn256, MultiSignature};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

pub fn verify_bls_signature<F: RichField>(
    hashed_message: HashOut<F>,
    signature: BlsSignature,
    keys: &[PublicKey],
) -> anyhow::Result<()> {
    let hashed_message = hashed_message.to_bytes();
    let keys = keys.iter().map(|key| key.0.as_slice()).collect::<Vec<_>>();
    let agg_pub_key = Bn256.aggregate_public_keys(&keys).unwrap();
    let result = Bn256.verify(&signature.0, &hashed_message, &agg_pub_key);
    match result {
        Ok(()) => Ok(()),
        _ => Err(anyhow!("bls verification error")),
    }
}

#[derive(Clone, Debug)]
pub struct BlsSignatureTarget(pub Vec<BoolTarget>);

impl BlsSignatureTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        todo!()
    }

    pub fn set_witness<F: RichField>(
        &self,
        _pw: &mut impl Witness<F>,
        _signature: &BlsSignature,
    ) -> anyhow::Result<()> {
        todo!()
    }
}

pub fn verify_bls_signature_target<F: RichField + Extendable<D>, const D: usize>(
    _builder: &mut CircuitBuilder<F, D>,
    _hashed_message: HashOutTarget,
    _signature: BlsSignatureTarget,
    _keys: &[AddressTarget],
) {
    todo!()
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::poseidon::PoseidonHash,
        plonk::config::Hasher,
    };

    use super::*;

    #[test]
    fn test_bls_signature() {
        type F = GoldilocksField;
        let secret_key_1 =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();

        let secret_key_2 =
            hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1")
                .unwrap();

        let public_key_1 = Bn256.derive_public_key(&secret_key_1).unwrap();
        let public_key_2 = Bn256.derive_public_key(&secret_key_2).unwrap();

        let hashed_message = PoseidonHash::hash_no_pad(&[F::ONE, F::TWO]);

        let sig_1 = Bn256
            .sign(&secret_key_1, &hashed_message.to_bytes())
            .unwrap();
        let sig_2 = Bn256
            .sign(&secret_key_2, &hashed_message.to_bytes())
            .unwrap();

        let agg_sig = Bn256.aggregate_signatures(&[&sig_1, &sig_2]).unwrap();

        let keys = &[PublicKey(public_key_1), PublicKey(public_key_2)];
        assert!(verify_bls_signature(hashed_message, BlsSignature(agg_sig), keys).is_ok());
    }
}
