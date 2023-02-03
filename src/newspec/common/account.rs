use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

/// Address of user account. This corresponds to the index of the world state tree.
#[derive(Clone, Debug, Default)]
pub struct Address<F: RichField>(pub F);

impl<F: RichField> Address<F> {
    pub(crate) fn to_vec(&self) -> Vec<F> {
        vec![self.0]
    }
}

#[derive(Clone, Debug, Default)]
pub struct Account<F: RichField> {
    pub private_key: Vec<F>,
    pub public_key: HashOut<F>,
    pub address: Address<F>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddressTarget(pub Target);

impl AddressTarget {
    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Address<F>,
    ) -> Self {
        Self(builder.constant(value.0))
    }

    pub(crate) fn to_vec(self) -> Vec<Target> {
        vec![self.0]
    }
}
