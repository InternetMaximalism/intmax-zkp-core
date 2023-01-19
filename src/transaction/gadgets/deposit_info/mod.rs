use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::{
    transaction::asset::VariableIndex,
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct DepositInfo<F: Field> {
    pub receiver_address: Address<F>,
    pub contract_address: Address<F>,
    pub variable_index: VariableIndex<F>,
    pub amount: F,
}

#[test]
fn test_serde_deposit_info() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    let deposit_info: DepositInfo<GoldilocksField> = DepositInfo::default();
    let _json = serde_json::to_string(&deposit_info).unwrap();
    let json = "{\"receiver_address\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"contract_address\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"variable_index\":\"0x00\",\"amount\":0}";
    let decoded_deposit_info: DepositInfo<_> = serde_json::from_str(json).unwrap();
    assert_eq!(decoded_deposit_info, deposit_info);

    let json_value = serde_json::to_value(deposit_info).unwrap();
    let decoded_deposit_info: DepositInfo<_> = serde_json::from_value(json_value).unwrap();
    assert_eq!(decoded_deposit_info, deposit_info);
}

#[derive(Clone, Copy, Debug)]
pub struct DepositInfoTarget {
    pub receiver_address: AddressTarget,
    pub contract_address: AddressTarget,
    pub variable_index: HashOutTarget,
    pub amount: Target,
}

impl DepositInfoTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let receiver_address = AddressTarget::add_virtual_to(builder);
        let contract_address = AddressTarget::add_virtual_to(builder);
        let variable_index = builder.add_virtual_hash();
        let amount = builder.add_virtual_target();

        Self {
            receiver_address,
            contract_address,
            variable_index,
            amount,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        value: DepositInfo<F>,
    ) {
        self.receiver_address
            .set_witness(pw, value.receiver_address);
        self.contract_address
            .set_witness(pw, value.contract_address);
        pw.set_hash_target(self.variable_index, value.variable_index.to_hash_out());
        pw.set_target(self.amount, value.amount);
    }
}
