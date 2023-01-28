use plonky2::iop::target::BoolTarget;

use crate::zkdsa::gadgets::account::AddressTarget;

#[derive(Clone, Copy, Debug)]
pub struct TransactionSenderWithValidityTarget {
    pub sender_address: AddressTarget,
    pub is_valid: BoolTarget,
}
