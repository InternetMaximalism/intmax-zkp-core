use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

use super::{
    account::{Address, AddressTarget},
    asset::{Asset, AssetTarget},
    block_header::{UINT256Target, UINT256},
    traits::{Leafable, LeafableTarget},
};

/// Transaction which specifies a sender, a reciever, an asset.
/// `amount` should be below `MAX_AMOUNT`
#[derive(Clone, Debug, Default)]
pub struct Transaction<F: RichField> {
    pub from: Address,
    pub to: Address,
    pub asset: Asset,
    /// Random value which randomize tx_hash
    pub nonce: [F; 4],
}

impl<F: RichField> Transaction<F> {
    pub(crate) fn to_vec(&self) -> Vec<F> {
        [
            self.from.to_vec(),
            self.to.to_vec(),
            self.asset.to_vec(),
            self.nonce.to_vec(),
        ]
        .concat()
    }
}

impl<F: RichField> Leafable<F> for Transaction<F> {
    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        H::hash_no_pad(&self.to_vec())
    }

    fn empty_leaf() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
pub struct TransactionTarget {
    pub from: AddressTarget,
    pub to: AddressTarget,
    pub asset: AssetTarget,
    pub nonce: [Target; 4],
}

impl TransactionTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let from = AddressTarget::new(builder);
        let to = AddressTarget::new(builder);
        let asset = AssetTarget::new(builder);
        let nonce = builder.add_virtual_target_arr::<4>();

        Self {
            from,
            to,
            asset,
            nonce,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        transaction: &Transaction<F>,
    ) -> anyhow::Result<()> {
        self.from.set_witness(pw, transaction.from)?;
        self.to.set_witness(pw, transaction.to)?;
        self.asset.set_witness(pw, &transaction.asset)?;

        anyhow::ensure!(self.nonce.len() == transaction.nonce.len());
        for (target, value) in self.nonce.iter().zip(transaction.nonce.iter()) {
            pw.set_target(*target, *value);
        }

        Ok(())
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Transaction<F>,
    ) -> Self {
        Self {
            from: AddressTarget::constant(builder, value.from),
            to: AddressTarget::constant(builder, value.to),
            asset: AssetTarget::constant(builder, value.asset),
            nonce: value.nonce.map(|v| builder.constant(v)),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<Target> {
        [
            self.from.to_vec(),
            self.to.to_vec(),
            self.asset.to_vec(),
            self.nonce.to_vec(),
        ]
        .concat()
    }
}

impl LeafableTarget for TransactionTarget {
    fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_or_noop::<H>(self.to_vec())
    }

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = Leafable::<F>::empty_leaf();

        Self::constant::<F, D>(builder, empty_leaf)
    }
}

/// Deposit tx from L1
#[derive(Clone)]
pub struct DepositTransaction {
    pub to: UINT256,
    pub kind: UINT256,
    pub amount: UINT256,
    /// To avoid collision of tx_hash
    pub block_number: UINT256,
}

impl DepositTransaction {
    // This hash logic should be verifiable on Solidity
    pub fn solidity_hash(&self) -> UINT256 {
        todo!()
    }
}

impl<F: RichField> Leafable<F> for DepositTransaction {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

pub struct DepositTransactionTarget {
    pub to: AddressTarget,
    pub kind: UINT256Target,
    pub amount: BigUintTarget,
    pub block_number: UINT256Target,
}

impl DepositTransactionTarget {
    // This hash logic should be verifiable on Solidity
    pub fn solidity_hash(&self) -> UINT256 {
        todo!()
    }
}

#[derive(Clone)]
/// Withdraw tx from L2
pub struct WithdrawTransaction {
    pub to: UINT256,
    pub kind: UINT256,
    pub amount: UINT256,
}

impl WithdrawTransaction {
    // This hash logic should be verifiable on Solidity
    pub fn solidity_hash(&self) -> UINT256 {
        todo!()
    }
}

impl<F: RichField> Leafable<F> for WithdrawTransaction {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash<H: Hasher<F>>(&self) -> H::Hash {
        todo!()
    }
}

pub struct WithdrawTransactionTarget {
    pub to: UINT256Target,
    pub kind: UINT256Target,
    pub amount: UINT256Target,
}

impl WithdrawTransactionTarget {
    // This hash logic should be verifiable on Solidity
    pub fn solidity_hash(&self) -> UINT256 {
        todo!()
    }
}
