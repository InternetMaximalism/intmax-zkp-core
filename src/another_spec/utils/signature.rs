use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::newspec::common::account::{Address, AddressTarget};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

pub fn verify_bls_signature<F: RichField>(
    _hashed_message: HashOut<F>,
    _signature: BlsSignature,
    _keys: &[Address],
) -> anyhow::Result<()> {
    todo!()
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
