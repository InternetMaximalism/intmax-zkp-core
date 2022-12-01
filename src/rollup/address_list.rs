use alloc::vec::Vec;
use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    plonk::config::GenericConfig,
};
use serde::{Deserialize, Serialize};

use crate::{
    transaction::circuits::MergeAndPurgeTransitionProofWithPublicInputs,
    zkdsa::{account::Address, circuits::SimpleSignatureProofWithPublicInputs},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Address<F>: Serialize",
    deserialize = "Address<F>: Deserialize<'de>"
))]
pub struct TransactionSenderWithValidity<F: Field> {
    pub sender_address: Address<F>,
    pub is_valid: bool,
}

pub fn make_address_list<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    user_tx_proofs: &[MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>],
    received_signatures: &[Option<SimpleSignatureProofWithPublicInputs<F, C, D>>],
    _num_transactions: usize,
) -> Vec<TransactionSenderWithValidity<F>> {
    user_tx_proofs
        .iter()
        .zip_eq(received_signatures.iter())
        .map(
            |(user_tx_proof, received_signature)| TransactionSenderWithValidity {
                sender_address: user_tx_proof.public_inputs.sender_address,
                is_valid: received_signature.is_some(),
            },
        )
        .collect::<Vec<_>>()
}
