use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};

use crate::newspec::common::account::{Address, AddressTarget, PrivateKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

pub fn verify_bls_signature<F: RichField>(
    hashed_message: HashOut<F>,
    signature: BlsSignature,
    keys: &[PrivateKey],
) -> anyhow::Result<()> {
    let hashed_message = hashed_message.to_bytes();
    let agg_pug_key = Bn256.aggregate_public_keys(keys.map(|key| key.0).collect());
    Bn256.verify(signature.0, hashed_message, agg_pub_key)?;
    Ok(())
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
