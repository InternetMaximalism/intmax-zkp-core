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
