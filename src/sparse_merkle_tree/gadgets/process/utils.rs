use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::sparse_merkle_tree::proof::ProcessMerkleProofRole;

use super::super::common::{
    enforce_equal_if_enabled, logical_and_not, logical_nor, logical_or, logical_xor,
};

// #[derive(Copy, Clone, Debug)]
// pub struct ProcessMerkleProofRoleTarget {
//     pub is_no_op: BoolTarget,
//     // pub is_insert_op: BoolTarget,
//     pub is_update_op: BoolTarget,
//     pub is_remove_op: BoolTarget,
//     pub is_insert_or_update_op: BoolTarget,
//     pub is_remove_or_update_op: BoolTarget,
//     pub is_insert_or_no_op: BoolTarget,
//     pub is_remove_or_no_op: BoolTarget,
//     pub is_insert_or_remove_op: BoolTarget,
//     pub is_update_or_no_op: BoolTarget,
//     pub is_not_no_op: BoolTarget,
// }

// pub fn get_process_merkle_proof_role<F: RichField + Extendable<D>, const D: usize>(
//     builder: &mut CircuitBuilder<F, D>,
//     fnc: [BoolTarget; 2],
// ) -> ProcessMerkleProofRoleTarget {
//     let is_no_op = logical_nor(builder, fnc[0], fnc[1]); // [0, 0]
//     let is_insert_op = logical_and_not(builder, fnc[0], fnc[1]); // [1, 0]
//     let is_update_op = logical_and_not(builder, fnc[1], fnc[0]); // [0, 1]
//     let is_remove_op = builder.and(fnc[0], fnc[1]); // [1, 1]
//     let is_insert_or_update_op = logical_xor(builder, fnc[0], fnc[1]); // [x, 1 - x]
//     let is_remove_or_update_op = fnc[1]; // [x, 1]
//     let is_insert_or_no_op = builder.not(fnc[1]); // [x, 0]
//     let is_remove_or_no_op = builder.not(is_insert_or_update_op); // [x, x]
//     let is_insert_or_remove_op = fnc[0]; // [1, x]
//     let is_update_or_no_op = builder.not(fnc[0]); // [0, x]
//     let is_not_no_op = logical_or(builder, fnc[0], fnc[1]);

//     ProcessMerkleProofRoleTarget {
//         is_no_op,
//         // is_insert_op,
//         is_update_op,
//         is_remove_op,
//         is_insert_or_update_op,
//         is_remove_or_update_op,
//         is_insert_or_no_op,
//         is_remove_or_no_op,
//         is_insert_or_remove_op,
//         is_update_or_no_op,
//         is_not_no_op,
//     }
// }

#[derive(Copy, Clone, Debug)]
pub struct ProcessMerkleProofRoleTarget(pub [BoolTarget; 2]);

impl ProcessMerkleProofRoleTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let fnc0 = builder.add_virtual_bool_target_safe();
        let fnc1 = builder.add_virtual_bool_target_safe();

        Self([fnc0, fnc1])
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, fnc: ProcessMerkleProofRole) {
        let fnc: [bool; 2] = fnc.into();
        pw.set_bool_target(self.0[0], fnc[0]);
        pw.set_bool_target(self.0[0], fnc[1]);
    }

    pub fn is_no_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        logical_nor(builder, self.0[0], self.0[1]) // [0, 0]
    }

    pub fn is_insert_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        logical_and_not(builder, self.0[0], self.0[1]) // [1, 0]
    }

    pub fn is_update_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        logical_and_not(builder, self.0[1], self.0[0]) // [0, 1]
    }

    pub fn is_remove_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        builder.and(self.0[0], self.0[1]) // [1, 1]
    }

    pub fn is_insert_or_update_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        logical_xor(builder, self.0[0], self.0[1]) // [x, 1 - x]
    }
    pub fn is_remove_or_update_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        self.0[1] // [x, 1]
    }

    pub fn is_insert_or_no_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        builder.not(self.0[1]) // [x, 0]
    }

    /// [x, x]
    pub fn is_remove_or_no_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let is_insert_or_update_op = self.is_insert_or_update_op(builder);
        builder.not(is_insert_or_update_op)
    }

    pub fn is_insert_or_remove_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        self.0[0] // [1, x]
    }

    pub fn is_update_or_no_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        builder.not(self.0[0]) // [0, x]
    }

    pub fn is_not_no_op<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        logical_or(builder, self.0[0], self.0[1])
    }
}

pub fn verify_smt_transition<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    cur_smt_fnc: [BoolTarget; 2],
    prev_new_smt_root: HashOutTarget,
    cur_old_smt_root: HashOutTarget,
) {
    let is_not_no_op = logical_or(builder, cur_smt_fnc[0], cur_smt_fnc[1]);

    enforce_equal_if_enabled(builder, prev_new_smt_root, cur_old_smt_root, is_not_no_op)
}

pub fn verify_layered_smt_target_connection<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    upper_smt_fnc: ProcessMerkleProofRoleTarget,
    old_upper_smt_value: HashOutTarget,
    new_upper_smt_value: HashOutTarget,
    old_lower_smt_root: HashOutTarget,
    new_lower_smt_root: HashOutTarget,
    // default_old_lower_smt_root: HashOutTarget,
    // default_new_lower_smt_root: HashOutTarget,
) {
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    let is_insert_or_no_op = upper_smt_fnc.is_insert_or_no_op(builder);
    let is_remove_or_no_op = upper_smt_fnc.is_remove_or_no_op(builder);
    let is_insert_or_update_op = upper_smt_fnc.is_insert_or_update_op(builder);
    let is_remove_or_update_op = upper_smt_fnc.is_remove_or_update_op(builder);

    enforce_equal_if_enabled(
        builder,
        old_lower_smt_root,
        default_hash, // default_old_lower_smt_root
        is_insert_or_no_op,
    );
    enforce_equal_if_enabled(
        builder,
        new_lower_smt_root,
        new_upper_smt_value,
        is_insert_or_update_op,
    );

    enforce_equal_if_enabled(
        builder,
        new_lower_smt_root,
        default_hash, // default_new_lower_smt_root
        is_remove_or_no_op,
    );
    enforce_equal_if_enabled(
        builder,
        old_lower_smt_root,
        old_upper_smt_value,
        is_remove_or_update_op,
    );
}
