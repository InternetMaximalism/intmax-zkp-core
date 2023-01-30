use super::{
    account::{Address, AddressTarget},
    asset::{TokenKind, TokenKindTarget},
    block::UINT256,
    traits::{HashableTarget, Leafable},
};
use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

/// Transaction which specifies a sender, a reciever, a token kind, and an amount.
/// `amount` should be below `MAX_AMOUNT`
pub struct Transaction<F: RichField> {
    pub from: Address<F>,
    pub to: Address<F>,
    pub kind: TokenKind<F>,
    pub amount: BigUint,
    /// Random value which randomize tx_hash
    pub nonce: [F; 4],
}

impl<F: RichField> Leafable<F> for Transaction<F> {
    fn default(&self) -> Self {
        todo!()
    }
    fn hash(&self) -> HashOut<F> {
        todo!()
    }
}

pub struct TransactionTarget {
    pub from: AddressTarget,
    pub to: AddressTarget,
    pub kind: TokenKindTarget,
    pub amount: BigUintTarget,
    pub nonce: [Target; 4],
}

impl<F: RichField + Extendable<D>, const D: usize> HashableTarget<F, D> for TransactionTarget {
    fn hash(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        todo!()
    }
}

/// Deposit tx from L1
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
