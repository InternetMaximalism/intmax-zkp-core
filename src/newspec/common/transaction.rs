use crate::transaction::asset::Asset;

use super::{
    account::{Address, AddressTarget},
    asset::AssetTarget,
    block_header::UINT256,
    traits::{HashableTarget, Leafable},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

/// Transaction which specifies a sender, a reciever, an asset.
/// `amount` should be below `MAX_AMOUNT`
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

    fn default_hash(&self) -> H::Hash {
        todo!()
    }
}

pub struct TransactionTarget {
    pub from: AddressTarget,
    pub to: AddressTarget,
    pub asset: AssetTarget,
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
