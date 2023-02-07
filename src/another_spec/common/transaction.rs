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
        common::asset::verify_amount_hash,
        utils::signature::{block_signature_is_valid, BlsSignature},
    },
    newspec::{
        common::{account::Address, traits::Leafable},
        utils::merkle_tree::merkle_tree::{verify_merkle_proof_with_leaf, MerkleTree},
    },
};

use super::{
    asset::{add_amounts, Assets},
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

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> TransferTree<F, H> {
    pub fn with_leaves(_transfers: &[Transfer]) -> Self {
        todo!()
    }
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

pub fn has_positive_balance<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    _account: Address, // L2 address
    /* private */ _block_header: BlockHeader<F>,
) -> anyhow::Result<()> {
    // let block_hash = block_header.get_block_hash::<H>();
    // let (total_amount_received_hash, total_amount_sent_hash) =
    //     is_greater_than::<F, H>(total_amount_received, total_amount_sent)?;

    // verify_total_amount_received_in_history::<F, H>(
    //     account,
    //     total_amount_received_hash,
    //     block_hash,
    // )?;

    // verify_total_amount_sent_in_history::<F, H>(account, total_amount_sent_hash, block_hash)?;

    todo!()
}

/// `payments` is a list of all payments to the account in the block.
/// Returns `(amount_received_hash, transfer_batch_hash)`
pub fn verify_amount_received_in_transfer_batch_conditional<
    F: RichField,
    H: Hasher<F, Hash = HashOut<F>>,
>(
    account: Address, // L1 address
    /* private */ transfer_batch: TransferBatch<F>,
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ payments: &[Payment<F, H>],
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

        // TODO: Check that the sender had enough balance to send the funds
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

// TODO: make a circuit
/// Returns `(last_block_hash, amount_received_before_last_block_hash, amount_received_in_last_block_hash, total_amount_received_hash)`
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn verify_total_amount_received_in_history<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ last_block_header: BlockHeader<F>,
    /* private */ amount_received_before_last_block: &Assets,
    /* private */ amount_received_in_last_block: &Assets,
    /* private */ total_amount_received: &Assets,
    /* private */ block_content: BlockContent<F>,
    /* private */ payments: &[Payment<F, H>],
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)> {
    // TODO: We decare and verify the amount received before the last block
    // verify_total_amount_received_in_history(
    //     account,
    //     amount_received_before_last_block_hash,
    //     last_block_header.previous_block_hash,
    // )?;

    // We decare and verify the amount received in the last block
    let (amount_received_in_last_block_hash, last_block_hash) =
        verify_amount_received_in_block::<F, H>(
            account,
            amount_received_in_last_block,
            last_block_header,
            block_content,
            payments,
            salt,
        )?;

    // We check that the sum is "total_amount_received_hash"
    let (amount_received_before_last_block_hash, _, total_amount_received_hash) =
        add_amounts::<F, H>(
            amount_received_before_last_block,
            amount_received_in_last_block,
            total_amount_received,
        )?;

    Ok((
        last_block_hash,
        amount_received_before_last_block_hash,
        amount_received_in_last_block_hash,
        total_amount_received_hash,
    ))
}

/// The following circuit verifies the total amount received by a list of L1 accounts. This is the
/// circuit that needs a proof which will be verified by the rollup contract when withdrawing to L1.
pub fn verify_total_amount_received_by_l1_addresses<
    F: RichField,
    H: Hasher<F, Hash = HashOut<F>>,
>(
    _total_amount_received: &[(Address, Assets)], // L1 address
    _block_hash: HashOut<F>,
) -> anyhow::Result<()> {
    // for (l1_address, amount) in total_amount_received {
    //     verify_total_amount_received_in_history(l1_address, amount, block_hash)?;
    // }
    todo!()
}

/// Returns `(amount_sent_in_transaction_hash, transfer_tree_root)`
pub fn verify_amount_sent_in_transaction<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    /* private */ amount_sent_in_transaction: &Assets,
    /* private */ transfers: &[Transfer],
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>)> {
    let amount_sent_in_transaction_hash =
        verify_amount_hash::<F, H>(amount_sent_in_transaction, salt)?;

    // We check that the transfer tree root is the correct merkle root of the tree consisting of all the given transfers.
    let transfer_tree_root = TransferTree::<F, H>::with_leaves(transfers)
        .merkle_tree
        .get_root();

    // We check that amount_sent_in_transaction is the sum of all amounts in the given transfers.
    let total_transfer_amount = transfers.iter().fold(Assets::default(), |acc, transfer| {
        acc + transfer.amount.clone()
    });
    anyhow::ensure!(&total_transfer_amount == amount_sent_in_transaction);

    Ok((amount_sent_in_transaction_hash, transfer_tree_root))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_amount_sent_in_transfer_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ amount_sent: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ transfer_batch: TransferBatch<F>,
    /* private */ transfer_merkle_proof: MerkleProof<F, H>,
    /* private */ transfers: &[Transfer],
    /* private */ salt: [F; 4],
) -> anyhow::Result<()> {
    anyhow::ensure!(transfer_batch.hash::<H>() == block_header.content_hash);

    // We only need to verify the amount sent if the account actually did send a transaction in the block,
    // which is determined by the following if-statement
    let content_hash = block_signature_is_valid::<F, H>(&transfer_batch)?;
    if transfer_batch.sender_list.iter().any(|v| v == &account)
        && content_hash == block_header.content_hash
    {
        // We check that the given transfer tree root is in the transaction tree.
        let (_, transfer_tree_root) =
            verify_amount_sent_in_transaction::<F, H>(amount_sent, transfers, salt)?;

        verify_merkle_proof_with_leaf(
            transfer_tree_root,
            account.0,
            transfer_batch.transaction_tree_root,
            &transfer_merkle_proof,
        )?;
    }

    Ok(())
}

pub fn verify_amount_sent_in_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ amount_sent_in_block: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ transfer_batch: TransferBatch<F>,
    /* private */ transfer_merkle_proof: MerkleProof<F, H>,
    /* private */ transfers: &[Transfer],
    /* private */ salt: [F; 4],
) -> anyhow::Result<()> {
    if block_header.content_type == BlockContentType::TransferBatch {
        verify_amount_sent_in_transfer_block::<F, H>(
            account,
            amount_sent_in_block,
            block_header,
            transfer_batch,
            transfer_merkle_proof,
            transfers,
            salt,
        )?;
    }

    Ok(())
}

// TODO: make a circuit
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn verify_total_amount_sent_in_history<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ last_block_header: BlockHeader<F>,
    /* private */ amount_sent_before_last_block: &Assets,
    /* private */ amount_sent_in_last_block: &Assets,
    /* private */ total_amount_sent: &Assets,
    /* private */ transfer_batch: TransferBatch<F>,
    /* private */ transfer_merkle_proof: MerkleProof<F, H>,
    /* private */ transfers: &[Transfer],
    /* private */ salt: [F; 4],
) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)> {
    // We decare and verify the last block header
    let last_block_hash = last_block_header.get_block_hash::<H>();

    // TODO: We decare and verify the amount sent before the last block
    // verify_total_amount_sent_in_history::<F, H>(
    //     account,
    //     amount_sent_before_last_block_hash,
    //     last_block_header.previous_block_hash,
    // )?;

    // We decare and verify the amount sent in the last block
    verify_amount_sent_in_block::<F, H>(
        account,
        amount_sent_in_last_block,
        last_block_header,
        transfer_batch,
        transfer_merkle_proof,
        transfers,
        salt,
    )?;

    // We ensure that the sum of the amount sent before the last block and the amount sent in the last block is equal to "total_amount_sent_hash"
    let (
        amount_sent_before_last_block_hash,
        amount_sent_in_last_block_hash,
        total_amount_sent_hash,
    ) = add_amounts::<F, H>(
        amount_sent_before_last_block,
        amount_sent_in_last_block,
        total_amount_sent,
    )?;

    Ok((
        last_block_hash,
        amount_sent_before_last_block_hash,
        amount_sent_in_last_block_hash,
        total_amount_sent_hash,
    ))
}
