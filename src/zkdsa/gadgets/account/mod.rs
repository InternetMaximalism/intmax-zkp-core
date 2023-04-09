use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
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

        let zero = builder.zero();
        builder.connect(target.elements[1], zero);
        builder.connect(target.elements[2], zero);
        builder.connect(target.elements[3], zero);

        Self(target)
    }

    pub fn set_witness<F: Field>(&self, pw: &mut impl Witness<F>, value: Address<F>) {
        pw.set_hash_target(self.0, HashOut::from_partial(&[value.0]));
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
