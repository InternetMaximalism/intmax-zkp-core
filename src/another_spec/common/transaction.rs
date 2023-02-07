use std::collections::HashMap;

use plonky2::{
    hash::{
        hash_types::{HashOut, RichField},
        merkle_proofs::MerkleProof,
    },
    plonk::config::Hasher,
};

use crate::{
    another_spec::{
        common::{asset::verify_amount_hash, block::has_positive_balance},
        utils::signature::{block_signature_is_valid, BlsSignature},
    },
    newspec::{
        common::{account::Address, traits::Leafable},
        utils::merkle_tree::merkle_tree::{verify_merkle_proof_with_leaf, MerkleTree},
    },
};

use super::{
    asset::Assets,
    block::{BlockContent, BlockContentType, BlockHeader},
};

#[derive(Clone, Debug)]
pub struct Transfer {
    pub recipient: Address,
    pub amount: Assets,
}

impl<F: RichField> Leafable<F> for Transfer {
    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }

    fn empty_leaf() -> Self {
        todo!()
    }
}

#[derive(Debug)]
pub struct TransferTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, Transfer>,
}

#[derive(Debug)]
pub struct TransactionTree<F: RichField, H: Hasher<F, Hash = HashOut<F>>> {
    pub merkle_tree: MerkleTree<F, H, HashOut<F>>,

    /// sender_address -> leaf_index
    pub address_map: HashMap<Address, usize>,
}

#[derive(Clone, Debug)]
pub struct TransferBatch<F: RichField> {
    /// The address of the aggregator for the block
    pub aggregator_address: Address,

    /// The list of senders in the block
    pub sender_list: Vec<Address>,

    /// The root of the transaction tree in the block
    pub transaction_tree_root: HashOut<F>,

    /// An aggregate signature of the transaction tree root by the senders in the block that received
    /// a merkle proof of their transaction in the transaction tree by the sequencer
    pub signature: BlsSignature,
}

impl<F: RichField> Leafable<F> for TransferBatch<F> {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct Deposit {
    pub recipient: Address,
    pub deposited_amount: Assets,
}

impl<F: RichField> Leafable<F> for Deposit {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

pub struct Payment<F: RichField, H: Hasher<F>> {
    pub sender: Address,
    pub transfer_tree_root: H::Hash,
    pub transfer_index: usize,
    pub transaction_merkle_proof: MerkleProof<F, H>,
    pub transfer_merkle_proof: MerkleProof<F, H>,
    pub transfer: Transfer,
}

/// Returns `(amount_received_hash, transfer_batch_hash)`
pub fn verify_amount_received_in_transfer_batch_conditional<
    F: RichField,
    H: Hasher<F, Hash = HashOut<F>>,
>(
    account: Address, // L1 address
    /* private */ transfer_batch: TransferBatch<F>,
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,

    // The following is a list of all payments to the account in the block. Each payment
    // contains the sender, the transfer tree root, the transfer index and the transfer.
    /* private */
    payments: &[Payment<F, H>],
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>)> {
    let transfer_batch_hash = transfer_batch.hash::<H>();
    let amount_received_hash = verify_amount_hash::<F, H>(amount_received, salt)?;

    let mut computed_amount_received = Assets::default();
    for payment in payments {
        verify_merkle_proof_with_leaf::<F, H, _>(
            payment.transfer_tree_root,
            payment.sender.0,
            transfer_batch.transaction_tree_root,
            &payment.transaction_merkle_proof,
        )?;

        verify_merkle_proof_with_leaf::<F, H, _>(
            payment.transfer.hash::<H>(),
            payment.transfer_index,
            payment.transfer_tree_root,
            &payment.transfer_merkle_proof,
        )?;

        // Check that the sender is in the sender_list for the block
        anyhow::ensure!(transfer_batch
            .sender_list
            .iter()
            .any(|v| v == &payment.sender));

        // Check that the sender had enough balance to send the funds
        has_positive_balance::<F, H>(payment.sender, block_header)?;

        anyhow::ensure!(payment.transfer.recipient == account);

        computed_amount_received += payment.transfer.amount.clone();
    }

    anyhow::ensure!(&computed_amount_received == amount_received);

    Ok((amount_received_hash, transfer_batch_hash))
}

/// Returns `(amount_received_hash, block_hash)`
pub fn verify_amount_received_in_transfer_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ transfer_batch: TransferBatch<F>,
    /* private */ payments: &[Payment<F, H>],
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>)> {
    let block_hash = block_header.get_block_hash::<H>();

    let transfer_batch_hash = block_signature_is_valid::<F, H>(&transfer_batch)?;
    anyhow::ensure!(block_header.content_hash == transfer_batch_hash);

    let (amount_received_hash, transfer_batch_hash) =
        verify_amount_received_in_transfer_batch_conditional::<F, H>(
            account,
            transfer_batch,
            amount_received,
            block_header,
            payments,
            salt,
        )?;
    anyhow::ensure!(block_header.content_hash == transfer_batch_hash);

    Ok((amount_received_hash, block_hash))
}

/// Returns `(amount_received_hash, block_hash)`
pub fn verify_amount_received_in_deposit_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ deposit: Deposit,
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>)> {
    let amount_received_hash = verify_amount_hash::<F, H>(amount_received, salt)?;

    let block_hash = block_header.get_block_hash::<H>();

    anyhow::ensure!(deposit.hash::<H>() == block_header.content_hash);

    anyhow::ensure!(amount_received == &Assets::default() || deposit.recipient == account);
    anyhow::ensure!(amount_received == &deposit.deposited_amount);

    Ok((amount_received_hash, block_hash))
}

/// Returns `(amount_received_hash, block_hash)`
pub fn verify_amount_received_in_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ block_content: BlockContent<F>,
    /* private */ payments: &[Payment<F, H>],
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>)> {
    if let BlockContent::Deposit(deposit) = block_content {
        anyhow::ensure!(block_header.content_type == BlockContentType::Deposit);
        verify_amount_received_in_deposit_block::<F, H>(
            account,
            amount_received,
            block_header,
            deposit,
            salt,
        )
    } else if let BlockContent::TransferBatch(transfer_batch) = block_content {
        anyhow::ensure!(block_header.content_type == BlockContentType::TransferBatch);
        verify_amount_received_in_transfer_block::<F, H>(
            account,
            amount_received,
            block_header,
            transfer_batch,
            payments,
            salt,
        )
    } else {
        let amount_received_hash = verify_amount_hash::<F, H>(&Assets::default(), salt)?;
        let block_hash = block_header.get_block_hash::<H>();

        Ok((amount_received_hash, block_hash))
    }
}
