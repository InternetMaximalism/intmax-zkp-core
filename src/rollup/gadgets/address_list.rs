use plonky2::{hash::hash_types::HashOutTarget, iop::target::BoolTarget};

#[derive(Clone, Copy, Debug)]
pub struct TransactionSenderWithValidityTarget {
    pub sender_address: HashOutTarget,
    pub is_valid: BoolTarget,
}
