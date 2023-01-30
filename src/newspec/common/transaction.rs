use super::{account::Address, asset::TokenKind};
use num::BigUint;
use plonky2::hash::hash_types::{HashOut, RichField};

/// Transaction which specifies a reciever, a token kind, and an amount.
/// `amount` should be below `MAX_AMOUNT`
pub struct Transaction<F: RichField> {
    pub to: Address<F>,
    pub kind: TokenKind<F>,
    pub amount: BigUint,
}

impl<F: RichField> Transaction<F> {
    pub fn default(&self) -> Self {
        todo!()
    }
    pub fn hash(&self, _nullifier: HashOut<F>) -> HashOut<F> {
        todo!()
    }
}
