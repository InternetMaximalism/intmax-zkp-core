use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use super::super::account::Address;

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct AddressTarget(pub HashOutTarget);

impl AddressTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let target = builder.add_virtual_hash();

        Self(target)
    }

    pub fn set_witness<F: Field>(&self, pw: &mut impl Witness<F>, value: Address<F>) {
        pw.set_hash_target(self.0, value.0);
    }

    pub fn read(inputs_t: &mut core::slice::Iter<Target>) -> Self {
        Self(HashOutTarget {
            elements: [
                *inputs_t.next().unwrap(),
                *inputs_t.next().unwrap(),
                *inputs_t.next().unwrap(),
                *inputs_t.next().unwrap(),
            ],
        })
    }
}
