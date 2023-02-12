use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

/// Address of user account. This corresponds to the index of the world state tree.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Address(pub usize);

impl Address {
    pub(crate) fn to_vec<F: RichField>(self) -> Vec<F> {
        assert!((self.0 as u64) < F::ORDER);

        vec![F::from_canonical_usize(self.0)]
    }
}

pub struct PrivateKey(pub Vec<u8>);
pub struct PublicKey(pub Vec<u8>);

#[derive(Clone, Debug, Default)]
pub struct Account<F: RichField> {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: Address,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddressTarget(pub Target);

impl AddressTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self(builder.add_virtual_target())
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        address: Address,
    ) -> anyhow::Result<()> {
        anyhow::ensure!((address.0 as u64) < F::ORDER);
        pw.set_target(self.0, F::from_canonical_usize(address.0));

        Ok(())
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        address: Address,
    ) -> Self {
        assert!((address.0 as u64) < F::ORDER);

        Self(builder.constant(F::from_canonical_usize(address.0)))
    }

    pub(crate) fn to_vec(self) -> Vec<Target> {
        vec![self.0]
    }
}
