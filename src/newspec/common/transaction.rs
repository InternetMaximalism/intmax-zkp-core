use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
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
    pub from: Address<F>,
    pub to: Address<F>,
    pub asset: Asset<F>,
    /// Random value which randomize tx_hash
    pub nonce: [F; 4],
}

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for Transaction<F> {
    fn hash(&self) -> H::Hash {
        todo!()
    }

    fn empty_leaf() -> Self {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct TransactionTarget {
    pub from: AddressTarget,
    pub to: AddressTarget,
    pub asset: AssetTarget,
    pub nonce: [Target; 4],
}

impl<F: RichField + Extendable<D>, const D: usize> LeafableTarget<F, D> for TransactionTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }

    fn empty_leaf(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
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

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for DepositTransaction {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash(&self) -> H::Hash {
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

impl<F: RichField, H: Hasher<F>> Leafable<F, H> for WithdrawTransaction {
    fn empty_leaf() -> Self {
        todo!()
    }

    fn hash(&self) -> H::Hash {
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
