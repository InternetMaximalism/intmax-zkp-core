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
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    another_spec::{
        circuits::{ReceivedAmountProofPublicInputsTarget, SentAmountProofPublicInputsTarget},
        utils::signature::{
            verify_bls_signature, verify_bls_signature_target, BlsSignature, BlsSignatureTarget,
        },
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
    recursion::make_recursion_constraints,
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

impl<F: RichField> TransferBatch<F> {
    pub fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct Payment<F: RichField> {
    pub sender: Address,
    pub transfer: Transfer,
    pub transaction_tree_root: HashOut<F>,
    pub total_amount_received: Assets,
    pub total_amount_sent: Assets,
}

#[derive(Clone, Debug)]
pub struct PaymentProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub content: Payment<F>,
    pub transaction_merkle_proof: MerkleProof<F, C::InnerHasher>,
    pub transfer_tree_root: HashOut<F>,
    pub transfer_index: usize,
    pub transfer_merkle_proof: MerkleProof<F, C::InnerHasher>,
    pub received_amount_proof: ProofWithPublicInputs<F, C, D>,
    pub sent_amount_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    PaymentProof<F, C, D>
{
    pub fn with_tree_height(_transaction_tree_height: usize, _transfer_tree_height: usize) -> Self {
        todo!()
    }

    pub fn calculate(&self) -> anyhow::Result<()> {
        verify_merkle_proof_with_leaf::<F, C::InnerHasher, _>(
            self.transfer_tree_root,
            self.content.sender.0,
            self.content.transaction_tree_root,
            &self.transaction_merkle_proof,
        )?;
        verify_merkle_proof_with_leaf::<F, C::InnerHasher, _>(
            self.content.transfer.hash::<C::InnerHasher>(),
            self.transfer_index,
            self.transfer_tree_root,
            &self.transfer_merkle_proof,
        )?;

        // TODO: verify recursive proof

        Ok(())
    }
}

/// `payments` is a list of all payments to the account in the block.
pub fn verify_amount_received_in_transfer_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address (?)
    amount_received: &Assets,
    block_header: BlockHeader<F>,
    transfer_batch: &TransferBatch<F>,
    payments: &[Payment<F>],
) -> anyhow::Result<()> {
    anyhow::ensure!(transfer_batch.hash::<H>() == block_header.content_hash);

    let sender_list = payments.iter().map(|v| v.sender).collect::<Vec<_>>();
    verify_bls_signature(
        transfer_batch.transaction_tree_root,
        transfer_batch.signature.clone(),
        &sender_list,
    )?;

    let mut computed_amount_received = Assets::default();
    for payment in payments.iter() {
        anyhow::ensure!(payment.transaction_tree_root == transfer_batch.transaction_tree_root);

        // Check that the sender is in the sender_list for the block
        // ensure sender in transfer_batch.sender_list

        // TODO: Check that the sender had enough balance to send the funds
        anyhow::ensure!(payment.total_amount_received <= payment.total_amount_sent);

        anyhow::ensure!(payment.transfer.recipient == account);

        computed_amount_received += payment.transfer.amount.clone();
    }

    anyhow::ensure!(&computed_amount_received == amount_received);

    Ok(())
}

pub fn verify_amount_received_in_deposit_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address (?)
    amount_received: &Assets,
    block_header: BlockHeader<F>,
    deposit: Transfer,
) -> anyhow::Result<()> {
    anyhow::ensure!(deposit.hash::<H>() == block_header.content_hash);

    anyhow::ensure!(amount_received == &Assets::default() || deposit.recipient == account);
    anyhow::ensure!(amount_received == &deposit.amount);

    Ok(())
}

pub fn verify_amount_received_in_block<F: RichField, H: Hasher<F, Hash = HashOut<F>>>(
    account: Address, // L1 address (?)
    amount_received: &Assets,
    block_header: BlockHeader<F>,
    block_content: BlockContent<F>,
    payments: &[Payment<F>],
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

pub struct ReceivedAmountProof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub account: Address, // L1 address (?)
    pub block_header: BlockHeader<F>,
    pub amount_received_until_last_block: Assets,
    pub amount_received_in_this_block: Assets,
    pub total_amount_received: Assets,
    pub block_content: BlockContent<F>,
    pub payment_proofs: Vec<PaymentProof<F, C, D>>,
    pub last_received_amount_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceivedAmountProof<F, C, D>
{
    // verify_total_amount_received_in_history
    /// Returns `(last_block_hash, amount_received_until_last_block_hash, amount_received_in_this_block_hash, total_amount_received_hash)`
    #[allow(clippy::type_complexity)]
    pub fn calculate(&self) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)> {
        // TODO: We decare and verify the amount received before the last block
        // verify_total_amount_received_in_history(
        //     account,
        //     amount_received_until_last_block_hash,
        //     last_block_header.previous_block_hash,
        // )?;

        // We decare and verify the amount received in the last block
        let payments = self
            .payment_proofs
            .iter()
            .map(|v| {
                v.calculate()?;

                Ok(v.content.clone())
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;
        verify_amount_received_in_block::<F, C::InnerHasher>(
            self.account,
            &self.amount_received_in_this_block,
            self.block_header,
            self.block_content.clone(),
            &payments,
        )?;

        // We check that the sum is "total_amount_received_hash"
        anyhow::ensure!(
            self.amount_received_until_last_block.clone()
                + self.amount_received_in_this_block.clone()
                == self.total_amount_received.clone()
        );

        let last_block_hash = self.block_header.hash::<C::InnerHasher>();

        let amount_received_until_last_block_hash = self
            .amount_received_until_last_block
            .hash_with_salt::<F, C::InnerHasher>();
        let amount_received_in_this_block_hash = self
            .amount_received_in_this_block
            .hash_with_salt::<F, C::InnerHasher>();
        let total_amount_received_hash = self
            .total_amount_received
            .hash_with_salt::<F, C::InnerHasher>();

        Ok((
            last_block_hash,
            amount_received_until_last_block_hash,
            amount_received_in_this_block_hash,
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
    block_header: BlockHeader<F>,
    transfer_batch: &TransferBatch<F>,
    transaction_merkle_proof: MerkleProof<F, H>,
    transfers: &[Transfer],
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
    amount_sent_in_block: &Assets,
    block_header: BlockHeader<F>,
    transfer_batch: &TransferBatch<F>,
    transaction_merkle_proof: MerkleProof<F, H>,
    transfers: &[Transfer],
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

pub struct SentAmountProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub account: Address,
    pub block_header: BlockHeader<F>,
    pub amount_sent_until_last_block: Assets,
    pub amount_sent_in_this_block: Assets,
    pub total_amount_sent: Assets,
    pub transfer_batch: TransferBatch<F>,
    pub transaction_merkle_proof: MerkleProof<F, C::InnerHasher>,
    pub transfers: Vec<Transfer>,
    pub last_sent_amount_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SentAmountProof<F, C, D>
{
    // verify_total_amount_sent_in_history
    /// Returns `(last_block_hash, amount_sent_until_last_block_hash, amount_sent_in_this_block_hash, total_amount_sent_hash)`
    #[allow(clippy::type_complexity)]
    pub fn calculate(&self) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)> {
        // TODO: We decare and verify the amount sent before the last block
        // verify_total_amount_sent_in_history::<F, H>(
        //     account,
        //     amount_sent_until_last_block_hash,
        //     last_block_header.previous_block_hash,
        // )?;

        // We decare and verify the amount sent in the last block
        verify_amount_sent_in_block::<F, C::InnerHasher>(
            self.account,
            &self.amount_sent_in_this_block,
            self.block_header,
            &self.transfer_batch,
            self.transaction_merkle_proof.clone(),
            &self.transfers,
        )?;

        // We ensure that the sum of the amount sent before the last block and the amount sent in the last block is equal to "total_amount_sent_hash"
        anyhow::ensure!(
            self.amount_sent_until_last_block.clone() + self.amount_sent_in_this_block.clone()
                == self.total_amount_sent.clone()
        );

        // We decare and verify the last block header
        let last_block_hash = self.block_header.hash::<C::InnerHasher>();

        let amount_sent_until_last_block_hash = self
            .amount_sent_until_last_block
            .hash_with_salt::<F, C::InnerHasher>();
        let amount_sent_in_this_block_hash = self
            .amount_sent_in_this_block
            .hash_with_salt::<F, C::InnerHasher>();
        let total_amount_sent_hash = self.total_amount_sent.hash_with_salt::<F, C::InnerHasher>();

        Ok((
            last_block_hash,
            amount_sent_until_last_block_hash,
            amount_sent_in_this_block_hash,
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

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        input: &Transfer,
    ) -> anyhow::Result<()> {
        self.recipient.set_witness::<F>(pw, input.recipient)?;
        self.amount.set_witness::<F>(pw, &input.amount)?;

        Ok(())
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
    pub sender: AddressTarget,
    pub transfer: TransferTarget,
    pub transaction_tree_root: HashOutTarget,
    pub total_amount_received: AssetsTarget,
    pub total_amount_sent: AssetsTarget,
}

impl PaymentTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let sender = AddressTarget::new(builder);
        let transfer = TransferTarget::new(builder);
        let transaction_tree_root = builder.add_virtual_hash();
        let total_amount_received = AssetsTarget::new(builder);
        let total_amount_sent = AssetsTarget::new(builder);

        Self {
            sender,
            transfer,
            transaction_tree_root,
            total_amount_received,
            total_amount_sent,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        _pw: &mut impl Witness<F>,
        _payment: &Payment<F>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PaymentProofTarget<const D: usize> {
    pub content: PaymentTarget,
    pub transaction_merkle_proof: MerkleProofTarget,
    pub transfer_tree_root: HashOutTarget,
    pub transfer_index: Target,
    pub transfer_merkle_proof: MerkleProofTarget,
    pub received_amount_proof: ProofWithPublicInputsTarget<D>,
    pub sent_amount_proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> PaymentProofTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        builder: &mut CircuitBuilder<F, D>,
        received_amount_circuit_data: &CircuitData<F, C, D>,
        sent_amount_circuit_data: &CircuitData<F, C, D>,
        transaction_tree_height: usize,
        transfer_tree_height: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let content = PaymentTarget::new(builder);
        let transfer_tree_root = builder.add_virtual_hash();
        let transfer_index = builder.add_virtual_target();
        let transaction_merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(transaction_tree_height),
        };
        let transfer_merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(transfer_tree_height),
        };
        let received_amount_proof =
            make_recursion_constraints(builder, received_amount_circuit_data);
        let sent_amount_proof = make_recursion_constraints(builder, sent_amount_circuit_data);

        let transfer_leaf_hash = content.transfer.hash::<F, C::InnerHasher, D>(builder);
        let transfer_index_bits =
            builder.split_le(transfer_index, transfer_merkle_proof.siblings.len());
        builder.verify_merkle_proof::<C::InnerHasher>(
            transfer_leaf_hash.elements.to_vec(),
            &transfer_index_bits,
            transfer_tree_root,
            &transfer_merkle_proof,
        );

        let sender_bits =
            builder.split_le(content.sender.0, transaction_merkle_proof.siblings.len());
        builder.verify_merkle_proof::<C::InnerHasher>(
            transfer_tree_root.elements.to_vec(),
            &sender_bits,
            content.transaction_tree_root,
            &transaction_merkle_proof,
        );

        let received_amount_proof_public_inputs =
            ReceivedAmountProofPublicInputsTarget::from_vec(&received_amount_proof.public_inputs);
        let total_amount_received_hash = content
            .total_amount_received
            .hash_with_salt::<F, C::InnerHasher, D>(builder);
        builder.connect_hashes(
            total_amount_received_hash,
            received_amount_proof_public_inputs.total_amount_received_hash,
        );

        let sent_amount_proof_public_inputs =
            SentAmountProofPublicInputsTarget::from_vec(&sent_amount_proof.public_inputs);
        let total_amount_sent_hash = content
            .total_amount_sent
            .hash_with_salt::<F, C::InnerHasher, D>(builder);
        builder.connect_hashes(
            total_amount_sent_hash,
            sent_amount_proof_public_inputs.total_amount_sent_hash,
        );

        Self {
            content,
            transaction_merkle_proof,
            transfer_tree_root,
            transfer_index,
            transfer_merkle_proof,
            received_amount_proof,
            sent_amount_proof,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        _pw: &mut impl Witness<F>,
        _payment_proof: &PaymentProof<F, C, D>,
    ) -> anyhow::Result<()> {
        todo!()

        // payment_proof.calculate()
    }
}

pub fn verify_amount_received_in_transfer_block_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    account: AddressTarget,
    amount_received: &AssetsTarget,
    block_header: BlockHeaderTarget,
    transfer_batch: &TransferBatchTarget,
    payments: &[PaymentTarget],
) {
    let transfer_batch_hash = transfer_batch.hash::<F, H, D>(builder); // deposit.hash
    builder.connect_hashes(block_header.content_hash, transfer_batch_hash);

    verify_bls_signature_target(
        builder,
        transfer_batch.transaction_tree_root,
        transfer_batch.signature.clone(),
        &transfer_batch.senders,
    );

    let mut computed_amount_received = AssetsTarget::constant::<F, D>(builder, Assets::default());
    for payment in payments.iter() {
        builder.connect_hashes(
            payment.transaction_tree_root,
            transfer_batch.transaction_tree_root,
        );

        // TODO: Check that the sender had enough balance to send the funds
        // total_amount_received.is_greater_than::<F, H>(builder, total_amount_sent);

        builder.connect(payment.transfer.recipient.0, account.0);

        computed_amount_received =
            AssetsTarget::add(builder, &computed_amount_received, &payment.transfer.amount);
    }

    AssetsTarget::connect(builder, &computed_amount_received, amount_received);
}

pub fn verify_amount_received_in_block_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    account: AddressTarget,
    amount_received: &AssetsTarget,
    block_header: BlockHeaderTarget,
    block_content: &TransferBatchTarget,
    payments: &[PaymentTarget],
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

#[derive(Clone, Debug)]
pub struct ReceivedAmountProofTarget<const D: usize> {
    pub account: AddressTarget,
    pub block_header: BlockHeaderTarget,
    pub total_amount_received_until_last_block: AssetsTarget,
    pub amount_received_in_this_block: AssetsTarget,
    pub total_amount_received: AssetsTarget,
    pub block_content: TransferBatchTarget,
    pub payment_proofs: Vec<PaymentProofTarget<D>>,
    pub last_received_amount_proof: ProofWithPublicInputsTarget<D>,
    pub block_hash: HashOutTarget,
    pub total_amount_received_hash: HashOutTarget,
}

impl<const D: usize> ReceivedAmountProofTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        builder: &mut CircuitBuilder<F, D>,
        received_amount_circuit_data: &CircuitData<F, C, D>,
        sent_amount_circuit_data: &CircuitData<F, C, D>,
        n_payments: usize,
        transaction_tree_height: usize,
        transfer_tree_height: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let block_header = BlockHeaderTarget::new(builder);
        let total_amount_received_until_last_block = AssetsTarget::new(builder);
        let amount_received_in_this_block = AssetsTarget::new(builder);
        let total_amount_received = AssetsTarget::new(builder);
        let block_content = TransferBatchTarget::new(builder, n_payments);
        let payment_proofs = (0..n_payments)
            .map(|_| {
                PaymentProofTarget::new::<F, C>(
                    builder,
                    received_amount_circuit_data,
                    sent_amount_circuit_data,
                    transaction_tree_height,
                    transfer_tree_height,
                )
            })
            .collect::<Vec<_>>();

        // TODO: We decare and verify the amount received before the last block
        let last_received_amount_proof =
            make_recursion_constraints(builder, received_amount_circuit_data);

        let last_received_amount_public_inputs = ReceivedAmountProofPublicInputsTarget::from_vec(
            &last_received_amount_proof.public_inputs,
        );
        let account = last_received_amount_public_inputs.account;

        // We decare and verify the amount received in the last block
        let payments = payment_proofs
            .iter()
            .map(|v| v.content.clone())
            .collect::<Vec<_>>();
        verify_amount_received_in_block_target::<F, C::InnerHasher, D>(
            builder,
            account,
            &amount_received_in_this_block,
            block_header,
            &block_content,
            &payments,
        );

        // We check that the sum is "total_amount_received_hash"
        let actual_total_amount_received = AssetsTarget::add::<F, D>(
            builder,
            &total_amount_received_until_last_block,
            &amount_received_in_this_block,
        );
        AssetsTarget::connect(
            builder,
            &actual_total_amount_received,
            &total_amount_received,
        );

        let block_hash = block_header.hash::<F, C::InnerHasher, D>(builder);
        let total_amount_received_until_last_block_hash =
            total_amount_received_until_last_block.hash_with_salt::<F, C::InnerHasher, D>(builder);
        builder.connect_hashes(
            last_received_amount_public_inputs.total_amount_received_hash,
            total_amount_received_until_last_block_hash,
        );
        // let amount_received_in_this_block_hash =
        //     amount_received_in_this_block.hash_with_salt::<F, C::InnerHasher, D>(builder);
        let total_amount_received_hash =
            total_amount_received.hash_with_salt::<F, C::InnerHasher, D>(builder);

        Self {
            account,
            block_header,
            total_amount_received_until_last_block,
            amount_received_in_this_block,
            total_amount_received,
            block_content,
            payment_proofs,
            last_received_amount_proof,
            block_hash,
            total_amount_received_hash,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        input: &ReceivedAmountProof<F, C, D>,
    ) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        self.account.set_witness(pw, input.account)?;
        self.block_header.set_witness(pw, &input.block_header);
        self.total_amount_received_until_last_block
            .set_witness(pw, &input.amount_received_until_last_block)?;
        self.amount_received_in_this_block
            .set_witness(pw, &input.amount_received_in_this_block)?;
        self.total_amount_received
            .set_witness(pw, &input.total_amount_received)?;
        let block_content = match &input.block_content {
            BlockContent::TransferBatch(transfer_batch) => transfer_batch.clone(),
            BlockContent::Deposit(_deposit) => TransferBatch {
                aggregator_address: Address::default(),
                senders: vec![Address::default()],
                transaction_tree_root: HashOut::ZERO,
                signature: BlsSignature(vec![]),
            },
        };
        self.block_content.set_witness::<F, C::InnerHasher>(
            pw,
            &block_content,
            input.block_header.content_type == BlockContentType::Deposit,
        )?;

        for (target, value) in self.payment_proofs.iter().zip(input.payment_proofs.iter()) {
            target.set_witness(pw, value)?;
        }
        pw.set_proof_with_pis_target::<C, D>(
            &self.last_received_amount_proof,
            &input.last_received_amount_proof,
        );

        input.calculate()
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
    block_header: BlockHeaderTarget,
    transfer_batch: &TransferBatchTarget,
    transaction_merkle_proof: MerkleProofTarget,
    transfers: &[TransferTarget],
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
    amount_sent_in_block: &AssetsTarget,
    block_header: BlockHeaderTarget,
    transfer_batch: &TransferBatchTarget,
    transaction_merkle_proof: MerkleProofTarget,
    transfers: &[TransferTarget],
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

#[derive(Clone, Debug)]
pub struct SentAmountProofTarget<const D: usize> {
    pub account: AddressTarget,
    pub block_header: BlockHeaderTarget,
    pub total_amount_sent_until_last_block: AssetsTarget,
    pub amount_sent_in_this_block: AssetsTarget,
    pub total_amount_sent: AssetsTarget,
    pub transfer_batch: TransferBatchTarget,
    pub transaction_merkle_proof: MerkleProofTarget,
    pub transfers: Vec<TransferTarget>,
    pub last_sent_amount_proof: ProofWithPublicInputsTarget<D>,
    pub block_hash: HashOutTarget,
    pub total_amount_sent_hash: HashOutTarget,
}

impl<const D: usize> SentAmountProofTarget<D> {
    // verify_total_amount_sent_in_history
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        builder: &mut CircuitBuilder<F, D>,
        sent_amount_circuit_data: &CircuitData<F, C, D>,
        n_payments: usize,
        n_transfers: usize,
        transaction_tree_height: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let block_header = BlockHeaderTarget::new(builder);
        let total_amount_sent_until_last_block = AssetsTarget::new(builder);
        let amount_sent_in_this_block = AssetsTarget::new(builder);
        let total_amount_sent = AssetsTarget::new(builder);
        let transfer_batch = TransferBatchTarget::new(builder, n_payments);
        let transaction_merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(transaction_tree_height),
        };
        let transfers = (0..n_transfers)
            .map(|_| TransferTarget::new(builder))
            .collect::<Vec<_>>();

        // We decare and verify the amount sent before the last block
        let last_sent_amount_proof = make_recursion_constraints(builder, sent_amount_circuit_data);

        let last_sent_amount_public_inputs =
            SentAmountProofPublicInputsTarget::from_vec(&last_sent_amount_proof.public_inputs);
        let account = last_sent_amount_public_inputs.account;

        // We decare and verify the amount sent in the last block
        verify_amount_sent_in_block_target::<F, C::InnerHasher, D>(
            builder,
            account,
            &amount_sent_in_this_block,
            block_header,
            &transfer_batch,
            transaction_merkle_proof.clone(),
            &transfers,
        );

        // We ensure that the sum of the amount sent before the last block and the amount sent in the last block is equal to "total_amount_sent_hash"
        let actual_total_amount_sent = AssetsTarget::add::<F, D>(
            builder,
            &total_amount_sent_until_last_block,
            &amount_sent_in_this_block,
        );
        AssetsTarget::connect(builder, &actual_total_amount_sent, &total_amount_sent);

        // We decare and verify the last block header
        let block_hash = block_header.hash::<F, C::InnerHasher, D>(builder);
        let total_amount_sent_until_last_block_hash =
            total_amount_sent_until_last_block.hash_with_salt::<F, C::InnerHasher, D>(builder);
        builder.connect_hashes(
            last_sent_amount_public_inputs.total_amount_sent_hash,
            total_amount_sent_until_last_block_hash,
        );
        // let amount_sent_in_this_block_hash =
        //     amount_sent_in_this_block.hash_with_salt::<F, C::InnerHasher, D>(builder);
        let total_amount_sent_hash =
            total_amount_sent.hash_with_salt::<F, C::InnerHasher, D>(builder);

        Self {
            account,
            block_header,
            total_amount_sent_until_last_block,
            amount_sent_in_this_block,
            total_amount_sent,
            transfer_batch,
            transaction_merkle_proof,
            transfers,
            last_sent_amount_proof,
            block_hash,
            total_amount_sent_hash,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        input: &SentAmountProof<F, C, D>,
    ) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>)>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        self.account.set_witness(pw, input.account)?;
        self.block_header.set_witness(pw, &input.block_header);
        self.total_amount_sent_until_last_block
            .set_witness(pw, &input.amount_sent_until_last_block)?;
        self.amount_sent_in_this_block
            .set_witness(pw, &input.amount_sent_in_this_block)?;
        self.total_amount_sent
            .set_witness(pw, &input.total_amount_sent)?;
        self.transfer_batch.set_witness::<F, C::InnerHasher>(
            pw,
            &input.transfer_batch,
            input.block_header.content_type == BlockContentType::Deposit,
        )?;
        for (target, value) in self
            .transaction_merkle_proof
            .siblings
            .iter()
            .zip(input.transaction_merkle_proof.siblings.iter())
        {
            pw.set_hash_target(*target, *value);
        }

        for (target, value) in self.transfers.iter().zip(input.transfers.iter()) {
            target.set_witness(pw, value)?;
        }
        pw.set_proof_with_pis_target::<C, D>(
            &self.last_sent_amount_proof,
            &input.last_sent_amount_proof,
        );

        input.calculate()
    }
}
