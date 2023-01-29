use plonky2::iop::target::{BoolTarget, Target};

use crate::zkdsa::gadgets::account::AddressTarget;

#[derive(Clone, Copy, Debug)]
pub struct TransactionSenderWithValidityTarget {
    pub sender_address: AddressTarget,
    pub is_valid: BoolTarget,
}

impl TransactionSenderWithValidityTarget {
    pub fn encode(&self) -> Vec<Target> {
        vec![vec![self.sender_address.0], vec![self.is_valid.target]].concat()
    }

    pub fn read(inputs: &mut core::slice::Iter<Target>) -> Self {
        Self {
            sender_address: AddressTarget(*inputs.next().unwrap()),
            is_valid: BoolTarget::new_unsafe(*inputs.next().unwrap()),
        }
    }
}
