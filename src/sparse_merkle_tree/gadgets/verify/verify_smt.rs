use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use super::super::super::{
    gadgets::common::{calc_internal_hash, calc_leaf_hash, smt_lev_ins},
    proof::SparseMerkleInclusionProof,
};

use crate::utils::{
    gadgets::logic::{enforce_equal_if_enabled, is_equal_hash_out, logical_and_not},
    hash::WrappedHashOut,
};

pub type SmtInclusionProof<F> =
    SparseMerkleInclusionProof<WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>>;

pub type LayeredSmtInclusionProof<F> = (SmtInclusionProof<F>, SmtInclusionProof<F>);

pub type LayeredLayeredSmtInclusionProof<F> = (
    SmtInclusionProof<F>,
    SmtInclusionProof<F>,
    SmtInclusionProof<F>,
);

#[derive(Clone, Debug)]
pub struct SparseMerkleInclusionProofTarget {
    pub siblings: Vec<HashOutTarget>,
    pub root: HashOutTarget,
    pub old_key: HashOutTarget,
    pub old_value: HashOutTarget,
    pub key: HashOutTarget,
    pub value: HashOutTarget,
    pub enabled: BoolTarget,
    pub is_old0: BoolTarget,
    pub fnc: BoolTarget,
}

impl SparseMerkleInclusionProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        n_levels: usize,
    ) -> Self {
        let siblings = builder.add_virtual_hashes(n_levels);
        let root = builder.add_virtual_hash();
        let old_key = builder.add_virtual_hash();
        let old_value = builder.add_virtual_hash();
        let key = builder.add_virtual_hash();
        let value = builder.add_virtual_hash();
        let enabled = builder.add_virtual_bool_target_safe();
        let is_old0 = builder.add_virtual_bool_target_safe();
        let fnc = builder.add_virtual_bool_target_safe();

        verify_smt_inclusion_proof::<F, H, D>(
            builder, &siblings, root, old_key, old_value, key, value, enabled, is_old0, fnc,
        );

        Self {
            siblings,
            root,
            old_key,
            old_value,
            key,
            value,
            enabled,
            is_old0,
            fnc,
        }
    }

    pub fn set_witness<F: Field>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &SmtInclusionProof<F>,
        enabled: bool,
    ) {
        assert!(witness.siblings.len() < self.siblings.len());
        for i in 0..witness.siblings.len() {
            pw.set_hash_target(self.siblings[i], *witness.siblings[i]);
        }
        for i in witness.siblings.len()..self.siblings.len() {
            pw.set_hash_target(self.siblings[i], HashOut::<F>::ZERO);
        }
        pw.set_hash_target(self.root, *witness.root);
        pw.set_hash_target(self.old_key, *witness.not_found_key);
        pw.set_hash_target(self.old_value, *witness.not_found_value);
        pw.set_hash_target(self.key, *witness.key);
        pw.set_hash_target(self.value, *witness.value);
        pw.set_bool_target(self.enabled, enabled);
        pw.set_bool_target(self.is_old0, witness.is_old0);
        pw.set_bool_target(self.fnc, !witness.found); // whether if this is a non-inclusion proof
    }
}

#[derive(Clone)]
pub struct VerifierLoopElt {
    pub top: BoolTarget,
    pub i0: BoolTarget,
    pub i_old: BoolTarget,
    pub i_new: BoolTarget,
    pub na: BoolTarget,
}

pub fn smt_verifier_level<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    st: VerifierLoopElt,
    sibling: HashOutTarget,
    old1_leaf: HashOutTarget,
    new1_leaf: HashOutTarget,
    lr_bit: BoolTarget,
    child: HashOutTarget,
) -> HashOutTarget {
    let VerifierLoopElt {
        top: st_top,
        i_old: st_i_old,
        i_new: st_i_new,
        ..
    } = st;

    let mut root = vec![];

    let hash_out = calc_internal_hash::<_, H, D>(builder, child, sibling, lr_bit);

    // st_top, st_i_old, st_i_new のうち 1 つだけが true であることを保証.
    // let selector = builder.add(builder.add(st_top.target, st_i_old.target), st_i_new.target);
    // builder.range_check(selector, 1);

    // let zero = HashOutTarget {
    //     elements: [builder.zero(); 4],
    // };
    // let aux0 = conditionally_select(&mut builder, hash_out, zero, st_top);
    // let aux1 = conditionally_select(&mut builder, old1_leaf, zero, st_i_old);
    // let aux2 = conditionally_select(&mut builder, new1_leaf, zero, st_i_new);
    // let root = aux0 + aux1 + aux2;

    for ((a_i, b_i), c_i) in hash_out
        .elements
        .into_iter()
        .zip(old1_leaf.elements.into_iter())
        .zip(new1_leaf.elements.into_iter())
    {
        let selected_a_i = builder.mul(a_i, st_top.target);
        let selected_b_i = builder.mul(b_i, st_i_old.target);
        let selected_c_i = builder.mul(c_i, st_i_new.target);
        let root_i = builder.add(selected_a_i, selected_b_i);
        let root_i = builder.add(root_i, selected_c_i);
        root.push(root_i);
    }

    HashOutTarget {
        elements: root.try_into().unwrap(),
    }
}

pub fn smt_verifier_sm<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    is0: BoolTarget,
    lev_ins: BoolTarget,
    fnc: BoolTarget,
    prev: VerifierLoopElt,
) -> VerifierLoopElt {
    let constant_true = builder.constant_bool(true);

    // aux1 = prev_top * levIns
    let aux1 = BoolTarget::new_unsafe(builder.mul(prev.top.target, lev_ins.target));

    // aux2 = prev_top * levIns * fnc
    let aux2 = BoolTarget::new_unsafe(builder.mul(aux1.target, fnc.target));

    // st_top = prev_top * (1-levIns)
    //    = + prev_top
    //      - prev_top * levIns
    let top = BoolTarget::new_unsafe(builder.sub(prev.top.target, aux1.target));

    // st_inew = prev_top * levIns * (1-fnc)
    //   = + prev_top * levIns
    //     - prev_top * levIns * fnc
    let i_new = BoolTarget::new_unsafe(builder.sub(aux1.target, aux2.target));

    // st_iold = prev_top * levIns * (1-is0)*fnc
    //   = + prev_top * levIns * fnc
    //     - prev_top * levIns * fnc * is0
    let i_old = builder.sub(constant_true.target, is0.target);
    let i_old = BoolTarget::new_unsafe(builder.mul(aux2.target, i_old));

    // st_i0 = prev_top * levIns * is0
    //  = + prev_top * levIns * is0
    let i0 = BoolTarget::new_unsafe(builder.mul(aux1.target, is0.target));

    // let na = prev.na
    //     .add(cs.namespace(|| "add pre.na to prev.i_new"), &prev.i_new)?
    //     .add(cs.namespace(|| "add na to prev.i_old"), &prev.i_old)?
    //     .add(cs.namespace(|| "add na to prev.i0"), &prev.i0)?;

    let prev_na_plus_prev_i_new = builder.add(prev.na.target, prev.i_new.target);
    let prev_na_plus_prev_i_new_plus_prev_i_old =
        builder.add(prev_na_plus_prev_i_new, prev.i_old.target);
    let na = BoolTarget::new_unsafe(
        builder.add(prev_na_plus_prev_i_new_plus_prev_i_old, prev.i0.target),
    );

    VerifierLoopElt {
        top,
        i_new,
        i_old,
        i0,
        na,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_smt_inclusion_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    siblings: &[HashOutTarget],
    root: HashOutTarget,
    old_key: HashOutTarget,
    old_value: HashOutTarget,
    key: HashOutTarget,
    value: HashOutTarget,
    enabled: BoolTarget,
    is_old0: BoolTarget,
    fnc: BoolTarget,
) {
    let constant_true = builder.constant_bool(true);
    let constant_false = builder.constant_bool(false);

    let num_levels = siblings.len();

    let hash1_old = calc_leaf_hash::<_, H, D>(builder, old_key, old_value);
    let hash1_new = calc_leaf_hash::<_, H, D>(builder, key, value);

    // let n2b_old = (0usize..4).flat_map(|i| builder.split_le(old_key.elements[i], 64)).collect::<Vec<_>>();
    let n2b_new = (0usize..4)
        .flat_map(|i| builder.split_le(key.elements[i], 64))
        .collect::<Vec<_>>();

    let lev_ins = smt_lev_ins(builder, enabled, siblings);

    let init_sm = VerifierLoopElt {
        top: enabled,
        i0: constant_false,
        i_old: constant_false,
        i_new: constant_false,
        na: BoolTarget::new_unsafe(builder.sub(constant_true.target, enabled.target)),
    };
    let mut sm: Vec<VerifierLoopElt> = vec![];
    for i in 0..num_levels {
        let prev = if i == 0 {
            init_sm.clone()
        } else {
            sm[i - 1].clone()
        };
        let st = smt_verifier_sm(builder, is_old0, lev_ins[i], fnc, prev);
        sm.push(st); // sm[i]
    }

    // let flag = sm[num_levels -1].na + sm[num_levels -1].i_old + sm[num_levels -1].i_new + sm[num_levels -1].i0;
    let flag = builder.add(
        sm[num_levels - 1].na.target,
        sm[num_levels - 1].i_old.target,
    );
    let flag = builder.add(flag, sm[num_levels - 1].i_new.target);
    let flag = builder.add(flag, sm[num_levels - 1].i0.target);

    // flag === 1;
    builder.connect(flag, constant_true.target);

    sm.reverse();

    let zero = HashOutTarget {
        elements: [builder.zero(); 4],
    };
    let mut levels: Vec<HashOutTarget> = vec![];
    for i in 0..num_levels {
        let child = if i == 0 { zero } else { levels[i - 1] };

        let levels_i = smt_verifier_level::<_, H, D>(
            builder,
            sm[i].clone(),
            siblings[num_levels - 1 - i],
            hash1_old,
            hash1_new,
            n2b_new[num_levels - 1 - i],
            child,
        );

        levels.push(levels_i);
    }

    levels.reverse();

    // Check that if checking for non inclusion and isOld0 == 0 then key != old_key
    let are_key_equals = is_equal_hash_out(builder, old_key, key);
    let flag = logical_and_not(builder, fnc, is_old0);
    let flag = builder.and(flag, enabled);
    let keys_ok = builder.and(flag, are_key_equals);
    builder.connect(keys_ok.target, constant_false.target);

    // Check the root
    enforce_equal_if_enabled(builder, root, levels[0], enabled);
}
