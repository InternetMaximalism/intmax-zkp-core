use super::account::Address;
use num::BigUint;
use plonky2::hash::hash_types::RichField;

pub struct TokenKind<F: RichField> {
    pub contract_address: Address<F>,
    pub variable_index: F,
}

pub struct Asset<F: RichField> {
    pub kind: TokenKind<F>,
    pub amount: BigUint,
}
