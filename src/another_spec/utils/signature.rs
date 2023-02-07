use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};

use crate::{
    another_spec::common::transaction::TransferBatch,
    newspec::common::{account::Address, traits::Leafable},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

/// Returns `transfer_batch_hash`
pub fn block_signature_is_valid<F: RichField, H: Hasher<F>>(
    /* private */ batch: &TransferBatch<F>,
) -> anyhow::Result<H::Hash> {
    let transfer_batch_hash = batch.hash::<H>();

    verify_bls_signature(
        batch.transaction_tree_root,
        batch.signature.clone(),
        &batch.sender_list,
    )?;

    Ok(transfer_batch_hash)
}

pub fn verify_bls_signature<F: RichField>(
    _message: HashOut<F>,
    _signature: BlsSignature,
    _keys: &[Address],
) -> anyhow::Result<()> {
    todo!()
}
