use alloc::vec::Vec;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use super::super::super::{goldilocks_poseidon::Wrapper, proof::SparseMerkleProcessProof};
use super::super::common::{
    calc_internal_hash, calc_leaf_hash, conditionally_reverse, conditionally_select,
    element_wise_add, enforce_equal_if_enabled, logical_and_not, logical_or, logical_xor,
    smt_lev_ins,
};
use super::utils::{get_process_merkle_proof_role, ProcessMerkleProofRoleTarget};

pub type SmtProcessProof<F> =
    SparseMerkleProcessProof<Wrapper<HashOut<F>>, Wrapper<HashOut<F>>, Wrapper<HashOut<F>>>;

pub type LayeredSmtProcessProof<F> = (SmtProcessProof<F>, SmtProcessProof<F>);

pub type LayeredLayeredSmtProcessProof<F> =
    (SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>);

#[derive(Clone, Debug)]
pub struct SparseMerkleProcessProofTarget<const N_LEVELS: usize> {
    pub siblings: [HashOutTarget; N_LEVELS],
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub old_key: HashOutTarget,
    pub old_value: HashOutTarget,
    pub new_key: HashOutTarget,
    pub new_value: HashOutTarget,
    pub is_old0: BoolTarget,
    pub fnc: [BoolTarget; 2],
}

impl<const N_LEVELS: usize> SparseMerkleProcessProofTarget<N_LEVELS> {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let siblings = builder.add_virtual_hashes(N_LEVELS);
        let old_root = builder.add_virtual_hash();
        let old_key = builder.add_virtual_hash();
        let old_value = builder.add_virtual_hash();
        let new_root = builder.add_virtual_hash();
        let new_key = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let is_old0 = builder.add_virtual_bool_target_safe();
        let fnc0 = builder.add_virtual_bool_target_safe();
        let fnc1 = builder.add_virtual_bool_target_safe();

        // let new_root =
        verify_smt_process_proof::<F, H, D>(
            builder,
            &siblings,
            old_root,
            old_key,
            old_value,
            new_root,
            new_key,
            new_value,
            is_old0,
            [fnc0, fnc1],
        );

        Self {
            siblings: siblings.try_into().unwrap(),
            old_root,
            new_root,
            old_key,
            old_value,
            new_key,
            new_value,
            is_old0,
            fnc: [fnc0, fnc1],
        }
    }

    pub fn set_witness<F: Field>(&self, pw: &mut impl Witness<F>, witness: &SmtProcessProof<F>) {
        assert!(witness.siblings.len() <= N_LEVELS);
        for i in 0..witness.siblings.len() {
            pw.set_hash_target(self.siblings[i], *witness.siblings[i]);
        }
        for i in witness.siblings.len()..N_LEVELS {
            pw.set_hash_target(self.siblings[i], HashOut::<F>::ZERO);
        }
        pw.set_hash_target(self.old_root, *witness.old_root);
        pw.set_hash_target(self.new_root, *witness.new_root);
        pw.set_hash_target(self.old_key, *witness.old_key);
        pw.set_hash_target(self.old_value, *witness.old_value);
        pw.set_hash_target(self.new_key, *witness.new_key);
        pw.set_hash_target(self.new_value, *witness.new_value);
        pw.set_bool_target(self.is_old0, witness.is_old0);

        let fnc: [bool; 2] = witness.fnc.into();
        pw.set_bool_target(self.fnc[0], fnc[0]);
        pw.set_bool_target(self.fnc[1], fnc[1]);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_smt_process_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    siblings: &[HashOutTarget],
    old_root: HashOutTarget,
    old_key: HashOutTarget,
    old_value: HashOutTarget,
    new_root: HashOutTarget,
    new_key: HashOutTarget,
    new_value: HashOutTarget,
    is_old0: BoolTarget,
    fnc: [BoolTarget; 2],
) {
    let constant_true = builder.constant_bool(true);
    let constant_false = builder.constant_bool(false);
    let zero = builder.zero();
    let default_hash = HashOutTarget::from_partial(&[], zero);
    let num_levels = siblings.len();

    let ProcessMerkleProofRoleTarget { is_remove_op, .. } =
        get_process_merkle_proof_role(builder, fnc);

    // remove proof は old と new をひっくり返せば insert proof になる
    let fnc0 = fnc[0];
    let fnc1 =
        BoolTarget::new_unsafe(builder._if(is_remove_op, constant_false.target, fnc[1].target));
    let fnc = [fnc0, fnc1];
    let (old_key, new_key) = conditionally_reverse(builder, old_key, new_key, is_remove_op);
    let (old_value, new_value) = conditionally_reverse(builder, old_value, new_value, is_remove_op);
    let (old_root, new_root) = conditionally_reverse(builder, old_root, new_root, is_remove_op);

    // この時点で remove proof を扱う必要がなくなった.
    let ProcessMerkleProofRoleTarget {
        is_not_no_op: enabled,
        is_no_op,
        is_remove_op,
        is_update_or_no_op,
        is_insert_or_remove_op,
        ..
    } = get_process_merkle_proof_role(builder, fnc);
    builder.connect(is_remove_op.target, constant_false.target);

    // component hash1Old = SMTHash1();
    // hash1Old.key <== oldKey;
    // hash1Old.value <== oldValue;
    let hash1_old = calc_leaf_hash::<F, H, D>(builder, old_key, old_value);

    // component hash1New = SMTHash1();
    // hash1New.key <== newKey;
    // hash1New.value <== newValue;
    let hash1_new = calc_leaf_hash::<F, H, D>(builder, new_key, new_value);

    // component n2bOld = Num2Bits_strict();
    // component n2bNew = Num2Bits_strict();
    // n2bOld.in <== oldKey;
    // n2bNew.in <== newKey;
    let n2b_old = old_key
        .elements
        .into_iter()
        .flat_map(|e| builder.split_le(e, 64))
        .collect::<Vec<_>>();
    let n2b_new = new_key
        .elements
        .into_iter()
        .flat_map(|e| builder.split_le(e, 64))
        .collect::<Vec<_>>(); // XXX: 529-530

    // component smtLevIns = SMTLevIns(nLevels);
    // for (i=0; i<nLevels; i++) smtLevIns.siblings[i] <== siblings[i];
    // smtLevIns.enabled <== enabled;
    let lev_ins = smt_lev_ins(builder, enabled, siblings);

    // component xors[nLevels];
    // for (i=0; i<nLevels; i++) {
    //     xors[i] = XOR();
    //     xors[i].a <== n2bOld.out[i];
    //     xors[i].b <== n2bNew.out[i];
    // }
    let xors = n2b_old
        .iter()
        .zip(n2b_new.iter())
        .map(|(a, b)| logical_xor(builder, *a, *b))
        .collect::<Vec<_>>();

    // component sm[nLevels];
    // for (i=0; i<nLevels; i++) {
    //     sm[i] = SMTProcessorSM();
    //     if (i==0) {
    //         sm[i].prev_top <== enabled;
    //         sm[i].prev_old0 <== 0;
    //         sm[i].prev_bot <== 0;
    //         sm[i].prev_new1 <== 0;
    //         sm[i].prev_na <== 1-enabled;
    //         sm[i].prev_upd <== 0;
    //     } else {
    //         sm[i].prev_top <== sm[i-1].st_top;
    //         sm[i].prev_old0 <== sm[i-1].st_old0;
    //         sm[i].prev_bot <== sm[i-1].st_bot;
    //         sm[i].prev_new1 <== sm[i-1].st_new1;
    //         sm[i].prev_na <== sm[i-1].st_na;
    //         sm[i].prev_upd <== sm[i-1].st_upd;
    //     }
    //     sm[i].is0 <== isOld0;
    //     sm[i].xor <== xors[i].out;
    //     sm[i].fnc[0] <== fnc[0];
    //     sm[i].fnc[1] <== fnc[1];
    //     sm[i].levIns <== smtLevIns.levIns[i];
    // }
    let mut prev = ProcessorLoopElt {
        top: enabled,
        old0: constant_false,
        new1: constant_false,
        bot: constant_false,
        na: builder.not(enabled),
        upd: constant_false,
    };
    let mut sm: Vec<ProcessorLoopElt> = Vec::with_capacity(num_levels);
    for i in 0..num_levels {
        let st = smt_processor_sm(
            builder,
            xors[i],
            is_old0,
            lev_ins[i],
            is_insert_or_remove_op,
            prev,
        );
        sm.push(st);

        prev = st;
    }

    // flag = sm[nLevels-1].st_na + sm[nLevels-1].st_new1 + sm[nLevels-1].st_old0 + sm[nLevels-1].st_upd;
    let tmp1 = logical_or(builder, sm[num_levels - 1].na, sm[num_levels - 1].new1);
    let tmp2 = logical_or(builder, sm[num_levels - 1].old0, sm[num_levels - 1].upd);
    let flag = logical_or(builder, tmp1, tmp2);

    // flag === 1;
    builder.connect(flag.target, constant_true.target);

    // component levels[nLevels];
    // for (i=nLevels-1; i != -1; i--)
    let mut prev_level = (default_hash, default_hash);
    for i in (0..num_levels).rev() {
        // levels[i] = SMTProcessorLevel();
        // levels[i].st_top <== sm[i].st_top;
        // levels[i].st_old0 <== sm[i].st_old0;
        // levels[i].st_bot <== sm[i].st_bot;
        // levels[i].st_new1 <== sm[i].st_new1;
        // levels[i].st_na <== sm[i].st_na;
        // levels[i].st_upd <== sm[i].st_upd;

        // levels[i].sibling <== siblings[i];
        // levels[i].old1leaf <== hash1Old.out;
        // levels[i].new1leaf <== hash1New.out;

        // levels[i].newlrbit <== n2bNew.out[i];
        // if (i==nLevels-1) {
        //     levels[i].oldChild <== 0;
        //     levels[i].newChild <== 0;
        // } else {
        //     levels[i].oldChild <== levels[i+1].oldRoot;
        //     levels[i].newChild <== levels[i+1].newRoot;
        // }
        let (old_child, new_child) = prev_level;
        prev_level = smt_processor_level::<F, H, D>(
            builder,
            sm[i],
            siblings[i],
            hash1_old,
            hash1_new,
            n2b_new[i],
            old_child,
            new_child,
        );
    }

    // component topSwitcher = Switcher();
    // topSwitcher.sel <== fnc[0]*fnc[1];
    // topSwitcher.L <== levels[0].oldRoot;
    // topSwitcher.R <== levels[0].newRoot;
    let top_switcher_out_l = prev_level.0;
    let top_switcher_out_r = prev_level.1;

    // NOTICE: noop のとき, siblings がすべて 0 なので, top_switcher_out_l, top_switcher_out_r の値はでたらめである.
    // component checkOldInput = ForceEqualIfEnabled();
    // checkOldInput.enabled <== enabled;
    // checkOldInput.in[0] <== oldRoot;
    // checkOldInput.in[1] <== topSwitcher.outL;
    // enforce_equal_if_enabled(builder, old_root, top_switcher_out_l, enabled);

    // newRoot <== enabled * (topSwitcher.outR - oldRoot) + oldRoot;
    // let expected_new_root = conditionally_select(builder, top_switcher_out_r, old_root, enabled);
    // builder.connect_hashes(expected_new_root, new_root);

    // topSwitcher.outL === oldRoot*enabled;
    // topSwitcher.outR === newRoot*enabled;
    enforce_equal_if_enabled(builder, top_switcher_out_l, old_root, enabled);
    enforce_equal_if_enabled(builder, top_switcher_out_r, new_root, enabled);

    // Check keys are equal if updating
    // component areKeyEquals = IsEqual();
    // areKeyEquals.in[0] <== oldKey;
    // areKeyEquals.in[1] <== newKey;
    // component keysOk = MultiAND(3);
    // keysOk.in[0] <== 1-fnc[0];
    // keysOk.in[1] <== fnc[1];
    // keysOk.in[2] <== 1-areKeyEquals.out;
    // keysOk.out === 0;
    // let fnc_is_update = logical_and_not(builder, fnc1, fnc0);
    enforce_equal_if_enabled(builder, old_key, new_key, is_update_or_no_op);
    enforce_equal_if_enabled(builder, old_root, new_root, is_no_op);
    enforce_equal_if_enabled(builder, old_value, new_value, is_no_op);
}

#[derive(Copy, Clone, Debug)]
pub struct ProcessorLoopElt {
    pub top: BoolTarget,
    pub old0: BoolTarget,
    pub bot: BoolTarget,
    pub new1: BoolTarget,
    pub na: BoolTarget,
    pub upd: BoolTarget,
}

#[allow(clippy::too_many_arguments)]
pub fn smt_processor_level<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    st: ProcessorLoopElt,
    sibling: HashOutTarget,
    old1_leaf: HashOutTarget,
    new1_leaf: HashOutTarget,
    new_lr_bit: BoolTarget,
    old_child: HashOutTarget,
    new_child: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let ProcessorLoopElt {
        top: st_top,
        old0: st_old0,
        new1: st_new1,
        bot: st_bot,
        upd: st_upd,
        ..
    } = st;

    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    let old_hash_out = calc_internal_hash::<F, H, D>(builder, old_child, sibling, new_lr_bit);

    // aux[0] <== old1leaf * (st_bot + st_new1 + st_upd);
    let st_bot_or_new1 = builder.add(st_bot.target, st_new1.target);
    let st_bot_or_new1_or_upd = builder.add(st_bot_or_new1, st_upd.target);
    let aux0 = conditionally_select(
        builder,
        old1_leaf,
        default_hash,
        BoolTarget::new_unsafe(st_bot_or_new1_or_upd),
    );

    // oldRoot <== aux[0] + oldProofHash.out * st_top;
    let a = conditionally_select(builder, old_hash_out, default_hash, st_top);
    let old_root = element_wise_add(builder, a, aux0);

    // aux[1] <== newChild * (st_top + st_bot);
    let st_top_or_bot = builder.add(st_top.target, st_bot.target);
    let aux1 = conditionally_select(
        builder,
        new_child,
        default_hash,
        BoolTarget::new_unsafe(st_top_or_bot),
    );

    // newSwitcher.L <== aux[1] + new1leaf*st_new1;
    let b = conditionally_select(builder, new1_leaf, default_hash, st_new1);
    let new_left_child = element_wise_add(builder, b, aux1);

    // aux[2] <== sibling*st_top;
    let aux2 = conditionally_select(builder, sibling, default_hash, st_top);

    // newSwitcher.R <== aux[2] + old1leaf*st_new1;
    let c = conditionally_select(builder, old1_leaf, default_hash, st_new1);
    let new_right_child = element_wise_add(builder, c, aux2);

    let new_hash_out =
        calc_internal_hash::<F, H, D>(builder, new_left_child, new_right_child, new_lr_bit);

    // aux[3] <== newProofHash.out * (st_top + st_bot + st_new1);
    let st_top_or_bot_or_new1 = builder.add(st_top_or_bot, st_new1.target);
    let aux3 = conditionally_select(
        builder,
        new_hash_out,
        default_hash,
        BoolTarget::new_unsafe(st_top_or_bot_or_new1),
    );

    // newRoot <==  aux[3] + new1leaf * (st_old0 + st_upd);
    let st_old0_or_upd = builder.add(st_old0.target, st_upd.target);
    let d = conditionally_select(
        builder,
        new1_leaf,
        default_hash,
        BoolTarget::new_unsafe(st_old0_or_upd),
    );
    let new_root = element_wise_add(builder, d, aux3);

    (old_root, new_root)
}

/// `isOldLev` 1 when is the level where oldLeaf is.
///
/// `xor` signal is 0 if the index bit at the current level is the same in the old
/// and the new index, and 1 if it is different.
///
/// `is0` signal is 1 if we are inserting/deleting in an empty leaf and 0 if we
/// are inserting/deleting in a leaf that contains an element.
///
/// The states are:
///
/// - `top`: While the index bits of the old and new index in the top level is the same, we are in the top state.
/// - `old0`: When the we reach insert level, we go to old0 state if `is0` = 1.
/// - `bot`: Once in insert level and `is0` = 0, we go to `bot` or `new1` level if `xor` = 1.
/// - `new1`: This level is reached when `xor` = 1. Here is where we insert/delete the hash of the
///  old and the new trees with just one element.
/// - `na`: Not applicable. After processing it, we go to the `na` level.
pub fn smt_processor_sm<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    xor: BoolTarget,
    is0: BoolTarget,
    lev_ins: BoolTarget,
    is_insert_or_remove_op: BoolTarget,
    prev: ProcessorLoopElt,
) -> ProcessorLoopElt {
    // aux1 = prev_top * levIns
    let aux1 = builder.and(prev.top, lev_ins);

    // aux2 = prev_top * levIns * fnc[0]
    let aux2 = builder.and(aux1, is_insert_or_remove_op);

    // st_top = prev_top * (1-levIns)
    //    = + prev_top
    //      - prev_top * levIns
    let top = logical_and_not(builder, prev.top, lev_ins);

    // st_old0 = prev_top * levIns * is0 * fnc[0]
    //      = + prev_top * levIns * is0 * fnc[0]         (= aux2 * is0)
    let old0 = builder.and(aux2, is0);

    // st_new1 = prev_top * levIns * (1-is0)*fnc[0] * xor   +  prev_bot*xor =
    //    = + prev_top * levIns *       fnc[0] * xor     (= aux2     * xor)
    //      - prev_top * levIns * is0 * fnc[0] * xor     (= st_old0  * xor)
    //      + prev_bot *                         xor     (= prev_bot * xor)
    let aux2_minus_old0 = logical_and_not(builder, aux2, is0);
    let aux2_minus_old0_plus_prev_bot = logical_or(builder, aux2_minus_old0, prev.bot);
    let new1 = builder.and(aux2_minus_old0_plus_prev_bot, xor);

    // st_bot = prev_top * levIns * (1-is0)*fnc[0] * (1-xor) + prev_bot*(1-xor);
    //    = + prev_top * levIns *       fnc[0]
    //      - prev_top * levIns * is0 * fnc[0]
    //      - prev_top * levIns *       fnc[0] * xor
    //      + prev_top * levIns * is0 * fnc[0] * xor
    //      + prev_bot
    //      - prev_bot *                         xor
    let bot = logical_and_not(builder, aux2_minus_old0_plus_prev_bot, xor);

    // st_upd = prev_top * (1-fnc[0]) *levIns;
    //    = + prev_top * levIns
    //      - prev_top * levIns * fnc[0]

    let upd = logical_and_not(builder, aux1, is_insert_or_remove_op);

    // st_na = prev_new1 + prev_old0 + prev_na + prev_upd;
    //    = + prev_new1
    //      + prev_old0
    //      + prev_na
    //      + prev_upd
    // NOTICE: or の代わりに add を使うとうまくいかない.
    // let prev_new1_plus_prev_old0 = builder.add(prev.new1.target, prev.old0.target);
    // let prev_new1_plus_prev_old0_plus_prev_na =
    //     builder.add(prev_new1_plus_prev_old0, prev.na.target);
    // let na =
    //     BoolTarget::new_unsafe(builder.add(prev_new1_plus_prev_old0_plus_prev_na, prev.upd.target));
    // builder.assert_bool(na);
    let prev_new1_plus_prev_old0 = logical_or(builder, prev.new1, prev.old0);
    let prev_new1_plus_prev_old0_plus_prev_na =
        logical_or(builder, prev_new1_plus_prev_old0, prev.na);
    let na = logical_or(builder, prev_new1_plus_prev_old0_plus_prev_na, prev.upd);

    ProcessorLoopElt {
        top,
        old0,
        new1,
        bot,
        na,
        upd,
    }
}
