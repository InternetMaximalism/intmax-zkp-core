use plonky2::{
    hash::hash_types::{HashOut, RichField},
    iop::target::Target,
};

/// Address of user account. This corresponds to the index of the world state tree.
#[derive(Clone, Debug, Default)]
pub struct Address<F: RichField>(pub F);

#[derive(Clone, Debug, Default)]
pub struct Account<F: RichField> {
    pub private_key: Vec<F>,
    pub public_key: HashOut<F>,
    pub address: Address<F>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddressTarget(pub Target);
