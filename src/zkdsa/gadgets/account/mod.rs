use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::poseidon::gadgets::poseidon_two_to_one;

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

pub fn private_key_to_public_key_target<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    private_key: HashOutTarget,
) -> HashOutTarget {
    poseidon_two_to_one::<F, H, D>(builder, private_key, private_key)
}
