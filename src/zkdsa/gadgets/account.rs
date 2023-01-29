use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use super::super::account::Address;

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct AddressTarget(pub Target);

impl AddressTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let target = builder.add_virtual_target();

        Self(target)
    }

    pub fn constant_default<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let target = builder.constant(F::ZERO);

        Self(target)
    }

    pub fn set_witness<F: Field>(&self, pw: &mut impl Witness<F>, value: Address<F>) {
        pw.set_target(self.0, value.0);
    }

    pub fn encode(&self) -> Vec<Target> {
        vec![self.0]
    }

    pub fn read(inputs: &mut core::slice::Iter<Target>) -> Self {
        Self(*inputs.next().unwrap())
    }
}

impl TryFrom<&[Target]> for AddressTarget {
    type Error = anyhow::Error;

    fn try_from(elements: &[Target]) -> Result<Self, Self::Error> {
        anyhow::ensure!(elements.len() == 1);
        Ok(Self(elements[0]))
    }
}
