use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::{MerkleProof, MerkleProofTarget},
    },
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use crate::{
    another_spec::utils::signature::{
        verify_bls_signature, verify_bls_signature_target, BlsSignature, BlsSignatureTarget,
    },
    merkle_tree::gadgets::get_merkle_root_target_from_leaves,
    newspec::{
        common::{
            account::{Address, AddressTarget},
            traits::Leafable,
        },
        utils::merkle_tree::merkle_tree::{
            verify_merkle_proof_with_leaf, verify_merkle_proof_with_leaf_target, MerkleTree,
        },
    },
    utils::gadgets::logic::logical_or,
};

use super::{
    asset::{Assets, AssetsTarget},
    block::{BlockContent, BlockContentType, BlockHeader, BlockHeaderTarget},
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
    pub senders: Vec<Address>,

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
pub struct Payment<F: RichField, H: Hasher<F>> {
    pub sender: Address,
    pub transfer_tree_root: H::Hash,
    pub transfer_index: usize,
    pub transaction_merkle_proof: MerkleProof<F, H>,
    pub transfer_merkle_proof: MerkleProof<F, H>,
    pub transfer: Transfer,
}

impl<F: RichField, H: Hasher<F>> Payment<F, H> {
    pub fn with_tree_height(_transaction_tree_height: usize, _transfer_tree_height: usize) -> Self {
        todo!()
    }
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
pub fn verify_amount_received_in_transfer_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address (?)
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ transfer_batch: &TransferBatch<F>,
    /* private */ payments: &[Payment<F, H>],
) -> anyhow::Result<()> {
    let sender_list = payments.iter().map(|v| v.sender).collect::<Vec<_>>();
    verify_bls_signature(
        transfer_batch.transaction_tree_root,
        transfer_batch.signature.clone(),
        &sender_list,
    )?;

    let mut computed_amount_received = Assets::default();
    for payment in payments.iter() {
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

        // TODO: Check that the sender had enough balance to send the funds
        has_positive_balance::<F, H>(payment.sender, block_header)?;

        anyhow::ensure!(payment.transfer.recipient == account);

        computed_amount_received += payment.transfer.amount.clone();
    }

    anyhow::ensure!(&computed_amount_received == amount_received);

    anyhow::ensure!(transfer_batch.hash::<H>() == block_header.content_hash);

    Ok(())
}

pub fn verify_amount_received_in_deposit_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address (?)
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ deposit: Transfer,
) -> anyhow::Result<()> {
    anyhow::ensure!(deposit.hash::<H>() == block_header.content_hash);

    anyhow::ensure!(amount_received == &Assets::default() || deposit.recipient == account);
    anyhow::ensure!(amount_received == &deposit.amount);

    Ok(())
}

pub fn verify_amount_received_in_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address (?)
    /* private */ amount_received: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ block_content: BlockContent<F>,
    /* private */ payments: &[Payment<F, H>],
) -> anyhow::Result<()> {
    match block_content {
        BlockContent::Deposit(deposit) => {
            anyhow::ensure!(block_header.content_type == BlockContentType::Deposit);
            verify_amount_received_in_deposit_block::<F, H>(
                account,
                amount_received,
                block_header,
                deposit,
            )
        }
        BlockContent::TransferBatch(transfer_batch) => {
            anyhow::ensure!(block_header.content_type == BlockContentType::TransferBatch);
            verify_amount_received_in_transfer_block::<F, H>(
                account,
                amount_received,
                block_header,
                &transfer_batch,
                payments,
            )
        }
    }
}

pub struct ReceivedAmountProof<F: RichField, H: Hasher<F>> {
    pub account: Address, // L1 address (?)
    pub last_block_header: BlockHeader<F>,
    pub amount_received_before_last_block: Assets,
    pub amount_received_in_last_block: Assets,
    pub total_amount_received: Assets,
    pub block_content: BlockContent<F>,
    pub payments: Vec<Payment<F, H>>,
}

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> ReceivedAmountProof<F, H> {
    // verify_total_amount_received_in_history
    /// Returns `(last_block_hash, amount_received_before_last_block_hash, amount_received_in_last_block_hash, total_amount_received_hash)`
    #[allow(clippy::type_complexity)]
    pub fn calculate(&self) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)> {
        // TODO: We decare and verify the amount received before the last block
        // verify_total_amount_received_in_history(
        //     account,
        //     amount_received_before_last_block_hash,
        //     last_block_header.previous_block_hash,
        // )?;

        // We decare and verify the amount received in the last block
        verify_amount_received_in_block::<F, H>(
            self.account,
            &self.amount_received_in_last_block,
            self.last_block_header,
            self.block_content.clone(),
            &self.payments,
        )?;

        // We check that the sum is "total_amount_received_hash"
        anyhow::ensure!(
            self.amount_received_before_last_block.clone()
                + self.amount_received_in_last_block.clone()
                == self.total_amount_received.clone()
        );

        let last_block_hash = self.last_block_header.hash::<H>();

        let amount_received_before_last_block_hash = self
            .amount_received_before_last_block
            .hash_with_salt::<F, H>();
        let amount_received_in_last_block_hash =
            self.amount_received_in_last_block.hash_with_salt::<F, H>();
        let total_amount_received_hash = self.total_amount_received.hash_with_salt::<F, H>();

        Ok((
            last_block_hash,
            amount_received_before_last_block_hash,
            amount_received_in_last_block_hash,
            total_amount_received_hash,
        ))
    }
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

/// Returns `amount_sent`
#[allow(clippy::too_many_arguments)]
pub fn verify_amount_sent_in_transfer_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ block_header: BlockHeader<F>,
    /* private */ transfer_batch: &TransferBatch<F>,
    /* private */ transaction_merkle_proof: MerkleProof<F, H>,
    /* private */ transfers: &[Transfer],
) -> anyhow::Result<Assets> {
    anyhow::ensure!(transfer_batch.hash::<H>() == block_header.content_hash);

    verify_bls_signature(
        transfer_batch.transaction_tree_root,
        transfer_batch.signature.clone(),
        &transfer_batch.senders,
    )?;

    // We only need to verify the amount sent if the account actually did send a transaction in the block,
    // which is determined by the following if-statement

    // We check that the transfer tree root is the correct merkle root of the tree consisting of all the given transfers.
    let transfer_tree_root = TransferTree::<F, H>::with_leaves(transfers)
        .merkle_tree
        .get_root();

    // We check that the given transfer tree root is in the transaction tree.
    verify_merkle_proof_with_leaf(
        transfer_tree_root,
        account.0,
        transfer_batch.transaction_tree_root,
        &transaction_merkle_proof,
    )?;

    let amount_sent = transfers.iter().fold(Assets::default(), |acc, transfer| {
        acc + transfer.amount.clone()
    });

    Ok(amount_sent)
}

pub fn verify_amount_sent_in_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address,
    /* private */ amount_sent_in_block: &Assets,
    /* private */ block_header: BlockHeader<F>,
    /* private */ transfer_batch: &TransferBatch<F>,
    /* private */ transaction_merkle_proof: MerkleProof<F, H>,
    /* private */ transfers: &[Transfer],
) -> anyhow::Result<()> {
    if block_header.content_type == BlockContentType::TransferBatch {
        let actual_amount_sent_in_block = verify_amount_sent_in_transfer_block::<F, H>(
            account,
            block_header,
            transfer_batch,
            transaction_merkle_proof,
            transfers,
        )?;
        anyhow::ensure!(&actual_amount_sent_in_block == amount_sent_in_block);
    }

    Ok(())
}

pub struct SentAmountProof<F: RichField, H: Hasher<F>> {
    pub account: Address,
    pub last_block_header: BlockHeader<F>,
    pub amount_sent_before_last_block: Assets,
    pub amount_sent_in_last_block: Assets,
    pub total_amount_sent: Assets,
    pub transfer_batch: TransferBatch<F>,
    pub transaction_merkle_proof: MerkleProof<F, H>,
    pub transfers: Vec<Transfer>,
}

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> SentAmountProof<F, H> {
    // verify_total_amount_sent_in_history
    /// Returns `(last_block_hash, amount_sent_before_last_block_hash, amount_sent_in_last_block_hash, total_amount_sent_hash)`
    #[allow(clippy::type_complexity)]
    pub fn calculate(&self) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)> {
        // TODO: We decare and verify the amount sent before the last block
        // verify_total_amount_sent_in_history::<F, H>(
        //     account,
        //     amount_sent_before_last_block_hash,
        //     last_block_header.previous_block_hash,
        // )?;

        // We decare and verify the amount sent in the last block
        verify_amount_sent_in_block::<F, H>(
            self.account,
            &self.amount_sent_in_last_block,
            self.last_block_header,
            &self.transfer_batch,
            self.transaction_merkle_proof.clone(),
            &self.transfers,
        )?;

        // We ensure that the sum of the amount sent before the last block and the amount sent in the last block is equal to "total_amount_sent_hash"
        anyhow::ensure!(
            self.amount_sent_before_last_block.clone() + self.amount_sent_in_last_block.clone()
                == self.total_amount_sent.clone()
        );

        // We decare and verify the last block header
        let last_block_hash = self.last_block_header.hash::<H>();

        let amount_sent_before_last_block_hash =
            self.amount_sent_before_last_block.hash_with_salt::<F, H>();
        let amount_sent_in_last_block_hash =
            self.amount_sent_in_last_block.hash_with_salt::<F, H>();
        let total_amount_sent_hash = self.total_amount_sent.hash_with_salt::<F, H>();

        Ok((
            last_block_hash,
            amount_sent_before_last_block_hash,
            amount_sent_in_last_block_hash,
            total_amount_sent_hash,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct TransferTarget {
    pub recipient: AddressTarget,
    pub amount: AssetsTarget,
}

impl TransferTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let recipient = AddressTarget::new(builder);
        let amount = AssetsTarget::new(builder);

        Self { recipient, amount }
    }
}

impl TransferTarget {
    pub fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct TransferBatchTarget {
    pub is_deposit: BoolTarget,

    /// The address of the aggregator for the block
    pub aggregator_address: AddressTarget,

    /// deposit の場合, 有効な senders の長さは 1
    pub senders: Vec<AddressTarget>,

    /// The root of the transaction tree in the block
    pub transaction_tree_root: HashOutTarget,

    /// An aggregate signature of the transaction tree root by the senders in the block that received
    /// a merkle proof of their transaction in the transaction tree by the sequencer
    pub signature: BlsSignatureTarget,
}

impl TransferBatchTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        n_payments: usize,
    ) -> Self {
        let is_deposit = builder.add_virtual_bool_target_safe();
        let aggregator_address = AddressTarget::new(builder);
        let senders = (0..n_payments)
            .map(|_| AddressTarget::new(builder))
            .collect::<Vec<_>>();
        let transaction_tree_root = builder.add_virtual_hash();
        let signature = BlsSignatureTarget::new(builder);

        Self {
            is_deposit,
            aggregator_address,
            senders,
            transaction_tree_root,
            signature,
        }
    }

    pub fn set_witness<F: RichField, H: Hasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        transfer_batch: &TransferBatch<F>,
        is_deposit: bool,
    ) -> anyhow::Result<()> {
        pw.set_bool_target(self.is_deposit, is_deposit);
        self.aggregator_address
            .set_witness(pw, transfer_batch.aggregator_address)?;
        for (target, value) in self.senders.iter().zip(transfer_batch.senders.iter()) {
            target.set_witness(pw, *value)?;
        }
        for target in self.senders.iter().skip(transfer_batch.senders.len()) {
            target.set_witness::<F>(pw, Address::default())?;
        }
        pw.set_hash_target(
            self.transaction_tree_root,
            transfer_batch.transaction_tree_root,
        );
        self.signature.set_witness(pw, &transfer_batch.signature)?;

        Ok(())
    }
}

impl TransferBatchTarget {
    pub fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct PaymentTarget {
    /// deposit の場合, payment.sender は zero address
    pub sender: AddressTarget,

    pub transfer_tree_root: HashOutTarget,
    pub transfer_index: Target,
    pub transfer_merkle_proof: MerkleProofTarget,

    pub transaction_merkle_proof: MerkleProofTarget,

    pub transfer: TransferTarget,
}

impl PaymentTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        transaction_tree_height: usize,
        transfer_tree_height: usize,
    ) -> Self {
        let sender = AddressTarget::new(builder);
        let transfer_tree_root = builder.add_virtual_hash();
        let transfer_index = builder.add_virtual_target();
        let transaction_merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(transaction_tree_height),
        };
        let transfer_merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(transfer_tree_height),
        };
        let transfer = TransferTarget::new(builder);

        Self {
            sender,
            transfer_tree_root,
            transfer_index,
            transaction_merkle_proof,
            transfer_merkle_proof,
            transfer,
        }
    }

    pub fn set_witness<F: RichField, H: Hasher<F>>(
        &self,
        _pw: &mut impl Witness<F>,
        _payment: &Payment<F, H>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

pub fn has_positive_balance_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    _builder: &mut CircuitBuilder<F, D>,
    _account: AddressTarget, // L2 address (deposit ならば zero address)
    /* private */ _block_header: BlockHeaderTarget,
) {
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

pub fn verify_amount_received_in_transfer_block_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    account: AddressTarget,
    /* private */ amount_received: &AssetsTarget,
    /* private */ block_header: BlockHeaderTarget,
    /* private */ transfer_batch: &TransferBatchTarget,
    /* private */ payments: &[PaymentTarget],
) {
    verify_bls_signature_target(
        builder,
        transfer_batch.transaction_tree_root,
        transfer_batch.signature.clone(),
        &transfer_batch.senders,
    );

    let mut computed_amount_received = AssetsTarget::constant::<F, D>(builder, Assets::default());
    for payment in payments.iter() {
        let transfer_leaf_hash = payment.transfer.hash::<F, H, D>(builder);
        let transfer_index_bits = builder.split_le(
            payment.transfer_index,
            payment.transfer_merkle_proof.siblings.len(),
        );
        builder.verify_merkle_proof::<H>(
            transfer_leaf_hash.elements.to_vec(),
            &transfer_index_bits,
            payment.transfer_tree_root,
            &payment.transfer_merkle_proof,
        );

        let sender_bits = builder.split_le(
            payment.sender.0,
            payment.transaction_merkle_proof.siblings.len(),
        );
        builder.verify_merkle_proof::<H>(
            payment.transfer_tree_root.elements.to_vec(),
            &sender_bits,
            transfer_batch.transaction_tree_root,
            &payment.transaction_merkle_proof,
        );

        // TODO: Check that the sender had enough balance to send the funds
        has_positive_balance_target::<F, H, D>(builder, payment.sender, block_header);

        builder.connect(payment.transfer.recipient.0, account.0);

        computed_amount_received =
            AssetsTarget::add(builder, &computed_amount_received, &payment.transfer.amount);
    }

    AssetsTarget::connect(builder, &computed_amount_received, amount_received);

    let transfer_batch_hash = transfer_batch.hash::<F, H, D>(builder); // deposit.hash
    builder.connect_hashes(block_header.content_hash, transfer_batch_hash);
}

pub fn verify_amount_received_in_block_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    account: AddressTarget,
    /* private */ amount_received: &AssetsTarget,
    /* private */ block_header: BlockHeaderTarget,
    /* private */ block_content: &TransferBatchTarget,
    /* private */ payments: &[PaymentTarget],
) {
    builder.connect(
        block_header.is_deposit.target,
        block_content.is_deposit.target,
    );
    verify_amount_received_in_transfer_block_target::<F, H, D>(
        builder,
        account,
        amount_received,
        block_header,
        block_content, // transfer_batch,
        payments,
    )
}

pub struct ReceivedAmountProofTarget {
    pub account: AddressTarget,
    /* private */ pub last_block_header: BlockHeaderTarget,
    /* private */ pub amount_received_before_last_block: AssetsTarget,
    /* private */ pub amount_received_in_last_block: AssetsTarget,
    /* private */ pub total_amount_received: AssetsTarget,
    /* private */ pub block_content: TransferBatchTarget,
    /* private */ pub payments: Vec<PaymentTarget>,
    pub last_block_hash: HashOutTarget,
    pub amount_received_before_last_block_hash: HashOutTarget,
    pub amount_received_in_last_block_hash: HashOutTarget,
    pub total_amount_received_hash: HashOutTarget,
}

impl ReceivedAmountProofTarget {
    pub fn new<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        n_payments: usize,
        transaction_tree_height: usize,
        transfer_tree_height: usize,
    ) -> Self {
        let account = AddressTarget::new(builder);
        let last_block_header = BlockHeaderTarget::new(builder);
        let amount_received_before_last_block = AssetsTarget::new(builder);
        let amount_received_in_last_block = AssetsTarget::new(builder);
        let total_amount_received = AssetsTarget::new(builder);
        let block_content = TransferBatchTarget::new(builder, n_payments);
        let payments = (0..n_payments)
            .map(|_| PaymentTarget::new(builder, transaction_tree_height, transfer_tree_height))
            .collect::<Vec<_>>();

        // TODO: We decare and verify the amount received before the last block
        // verify_total_amount_received_in_history(
        //     account,
        //     amount_received_before_last_block_hash,
        //     last_block_header.previous_block_hash,
        // )?;

        // We decare and verify the amount received in the last block
        verify_amount_received_in_block_target::<F, H, D>(
            builder,
            account,
            &amount_received_in_last_block,
            last_block_header,
            &block_content,
            &payments,
        );

        // We check that the sum is "total_amount_received_hash"
        let actual_total_amount_received = AssetsTarget::add::<F, D>(
            builder,
            &amount_received_before_last_block,
            &amount_received_in_last_block,
        );
        AssetsTarget::connect(
            builder,
            &actual_total_amount_received,
            &total_amount_received,
        );

        let last_block_hash = last_block_header.hash::<F, H, D>(builder);
        let amount_received_before_last_block_hash =
            amount_received_before_last_block.hash_with_salt::<F, H, D>(builder);
        let amount_received_in_last_block_hash =
            amount_received_in_last_block.hash_with_salt::<F, H, D>(builder);
        let total_amount_received_hash = total_amount_received.hash_with_salt::<F, H, D>(builder);

        Self {
            account,
            last_block_header,
            amount_received_before_last_block,
            amount_received_in_last_block,
            total_amount_received,
            block_content,
            payments,
            last_block_hash,
            amount_received_before_last_block_hash,
            amount_received_in_last_block_hash,
            total_amount_received_hash,
        }
    }
}

/// Returns `amount_sent`
#[allow(clippy::too_many_arguments)]
pub fn verify_amount_sent_in_transfer_block_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    account: AddressTarget,
    /* private */ block_header: BlockHeaderTarget,
    /* private */ transfer_batch: &TransferBatchTarget,
    /* private */ transaction_merkle_proof: MerkleProofTarget,
    /* private */ transfers: &[TransferTarget],
) -> AssetsTarget {
    let content_hash = transfer_batch.hash::<F, H, D>(builder);
    builder.connect_hashes(content_hash, block_header.content_hash);

    verify_bls_signature_target::<F, D>(
        builder,
        transfer_batch.transaction_tree_root,
        transfer_batch.signature.clone(),
        &transfer_batch.senders,
    );

    // We only need to verify the amount sent if the account actually did send a transaction in the block,
    // which is determined by the following if-statement

    // We check that the transfer tree root is the correct merkle root of the tree consisting of all the given transfers.
    let transfer_hashes = transfers
        .iter()
        .map(|v| v.hash::<F, H, D>(builder))
        .collect::<Vec<_>>();
    let transfer_tree_root =
        get_merkle_root_target_from_leaves::<F, H, D>(builder, transfer_hashes);

    // We check that the given transfer tree root is in the transaction tree.
    verify_merkle_proof_with_leaf_target::<F, H, _, D>(
        builder,
        transfer_tree_root,
        account.0,
        transfer_batch.transaction_tree_root,
        &transaction_merkle_proof,
    );

    transfers.iter().fold(
        AssetsTarget::constant(builder, Assets::default()),
        |acc, transfer| AssetsTarget::add(builder, &acc, &transfer.amount),
    )
}

pub fn verify_amount_sent_in_block_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    account: AddressTarget,
    /* private */ amount_sent_in_block: &AssetsTarget,
    /* private */ block_header: BlockHeaderTarget,
    /* private */ transfer_batch: &TransferBatchTarget,
    /* private */ transaction_merkle_proof: MerkleProofTarget,
    /* private */ transfers: &[TransferTarget],
) {
    let actual_amount_sent_in_block = verify_amount_sent_in_transfer_block_target::<F, H, D>(
        builder,
        account,
        block_header,
        transfer_batch,
        transaction_merkle_proof,
        transfers,
    );

    // If this block is not a deposit, `amount_sent_in_block` is the same with the sum of `transfers`.
    let tmp = AssetsTarget::is_equal(builder, &actual_amount_sent_in_block, amount_sent_in_block);
    let tmp = logical_or(builder, block_header.is_deposit, tmp);
    let constant_false = builder.constant_bool(false);
    builder.connect(tmp.target, constant_false.target);
}

pub struct SentAmountProofTarget {
    pub account: AddressTarget,
    /* private */ pub last_block_header: BlockHeaderTarget,
    /* private */ pub amount_sent_before_last_block: AssetsTarget,
    /* private */ pub amount_sent_in_last_block: AssetsTarget,
    /* private */ pub total_amount_sent: AssetsTarget,
    /* private */ pub transfer_batch: TransferBatchTarget,
    /* private */ pub transaction_merkle_proof: MerkleProofTarget,
    /* private */ pub transfers: Vec<TransferTarget>,
    pub last_block_hash: HashOutTarget,
    pub amount_sent_before_last_block_hash: HashOutTarget,
    pub amount_sent_in_last_block_hash: HashOutTarget,
    pub total_amount_sent_hash: HashOutTarget,
}

impl SentAmountProofTarget {
    // verify_total_amount_sent_in_history
    pub fn new<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        n_payments: usize,
        n_transfers: usize,
        transaction_tree_height: usize,
    ) -> Self {
        let account = AddressTarget::new(builder);
        let last_block_header = BlockHeaderTarget::new(builder);
        let amount_sent_before_last_block = AssetsTarget::new(builder);
        let amount_sent_in_last_block = AssetsTarget::new(builder);
        let total_amount_sent = AssetsTarget::new(builder);
        let transfer_batch = TransferBatchTarget::new(builder, n_payments);
        let transaction_merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(transaction_tree_height),
        };
        let transfers = (0..n_transfers)
            .map(|_| TransferTarget::new(builder))
            .collect::<Vec<_>>();

        // TODO: We decare and verify the amount sent before the last block
        // verify_total_amount_sent_in_history::<F, H>(
        //     account,
        //     amount_sent_before_last_block_hash,
        //     last_block_header.previous_block_hash,
        // )?;

        // We decare and verify the amount sent in the last block
        verify_amount_sent_in_block_target::<F, H, D>(
            builder,
            account,
            &amount_sent_in_last_block,
            last_block_header,
            &transfer_batch,
            transaction_merkle_proof.clone(),
            &transfers,
        );

        // We ensure that the sum of the amount sent before the last block and the amount sent in the last block is equal to "total_amount_sent_hash"
        let actual_total_amount_sent = AssetsTarget::add::<F, D>(
            builder,
            &amount_sent_before_last_block,
            &amount_sent_in_last_block,
        );
        AssetsTarget::connect(builder, &actual_total_amount_sent, &total_amount_sent);

        // We decare and verify the last block header
        let last_block_hash = last_block_header.hash::<F, H, D>(builder);

        let amount_sent_before_last_block_hash =
            amount_sent_before_last_block.hash_with_salt::<F, H, D>(builder);
        let amount_sent_in_last_block_hash =
            amount_sent_in_last_block.hash_with_salt::<F, H, D>(builder);
        let total_amount_sent_hash = total_amount_sent.hash_with_salt::<F, H, D>(builder);

        Self {
            account,
            last_block_header,
            amount_sent_before_last_block,
            amount_sent_in_last_block,
            total_amount_sent,
            transfer_batch,
            transaction_merkle_proof,
            transfers,
            last_block_hash,
            amount_sent_before_last_block_hash,
            amount_sent_in_last_block_hash,
            total_amount_sent_hash,
        }
    }
}
