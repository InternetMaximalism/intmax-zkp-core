use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{target::BoolTarget, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use crate::{
    merkle_tree::sparse_merkle_tree::SparseMerkleTreeMemory,
    poseidon::gadgets::poseidon_two_to_one,
    sparse_merkle_tree::{
        gadgets::common::conditionally_reverse, goldilocks_poseidon::WrappedHashOut, tree::KeyLike,
    },
    transaction::asset::Asset,
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

use super::asset_mess::{verify_equal_assets, AssetTarget};

pub fn encode_asset<F: RichField>(asset: &Asset<F>) -> Vec<F> {
    [
        asset.kind.contract_address.0.elements.to_vec(),
        asset.kind.variable_index.to_hash_out().elements.to_vec(),
        vec![F::from_canonical_u64(asset.amount)],
    ]
    .concat()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeInputProcessProof<F: RichField, H: Hasher<F>, K: KeyLike> {
    siblings: Vec<H::Hash>,
    index: K,
    old_leaf_data: Asset<F>,
}

#[derive(Clone, Debug)]
pub struct PurgeInputProcessProofTarget {
    siblings: Vec<HashOutTarget>,
    index: Vec<BoolTarget>,
    old_leaf_data: AssetTarget,
}

impl PurgeInputProcessProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_kinds: usize,
    ) -> Self {
        let siblings = builder.add_virtual_hashes(log_max_n_kinds);
        let index = (0..log_max_n_kinds)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();
        let old_leaf_data = AssetTarget {
            contract_address: builder.add_virtual_hash(),
            token_id: builder.add_virtual_hash(),
            amount: builder.add_virtual_target(),
        };

        Self {
            siblings,
            index,
            old_leaf_data,
        }
    }

    pub fn set_witness<F: RichField, H: Hasher<F, Hash = HashOut<F>>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &PurgeInputProcessProof<F, H, K>,
    ) {
        // let (w1, index, old_leaf_data) = witness;
        // assert_eq!(w0.old_root, prev_user_asset_root);
        // prev_user_asset_root = w0.new_root;

        let index = witness.index.to_bits();
        let mut w1_old_root = H::hash_or_noop(&encode_asset(&witness.old_leaf_data));
        let mut w1_new_root = H::hash_or_noop(&encode_asset(&Asset::default()));
        assert_eq!(index.len(), witness.siblings.len());
        for (lr_bit, sibling) in index.iter().zip(witness.siblings.iter()) {
            if *lr_bit {
                w1_old_root = H::two_to_one(*sibling, w1_old_root);
                w1_new_root = H::two_to_one(*sibling, w1_new_root);
            } else {
                w1_old_root = H::two_to_one(w1_old_root, *sibling);
                w1_new_root = H::two_to_one(w1_new_root, *sibling);
            }
        }

        // let merge_key = w0.new_key;
        // let old_root_with_nonce = PoseidonHash::two_to_one(w1_old_root, *merge_key).into();
        // let new_root_with_nonce = PoseidonHash::two_to_one(w1_new_root, *merge_key).into();
        // assert_eq!(w0.fnc, ProcessMerkleProofRole::ProcessUpdate);
        // verify_layered_smt_connection(
        //     w0.fnc,
        //     w0.old_value,
        //     w0.new_value,
        //     old_root_with_nonce,
        //     new_root_with_nonce,
        // )
        // .unwrap_or_else(|_| {
        //     panic!(
        //         "invalid connection between first and second SMT proof of index {} in input witnesses",
        //         i
        //     )
        // }); // XXX
        // assert!(
        //     w1.fnc == ProcessMerkleProofRole::ProcessUpdate
        //         || w1.fnc == ProcessMerkleProofRole::ProcessDelete
        // );
        // verify_layered_smt_connection(
        //     w1.fnc,
        //     w1.old_value,
        //     w1.new_value,
        //     w2.old_root,
        //     w2.new_root,
        // )
        // .unwrap_or_else(|_| {
        //     panic!(
        //         "invalid connection between second and third SMT proof of index {} in input witnesses",
        //         i
        //     )
        // });
        // assert_eq!(old_leaf_data.fnc, ProcessMerkleProofRole::ProcessDelete);
        // assert!(w2.old_value.elements[0].to_canonical_u64() < 1u64 << 56);
        // assert_eq!(w2.old_value.elements[1], F::ZERO);
        // assert_eq!(w2.old_value.elements[2], F::ZERO);
        // assert_eq!(w2.old_value.elements[3], F::ZERO);
        assert!(witness.old_leaf_data.amount < 1u64 << 56);

        // p0_t.set_witness(pw, w0);
        for (ht, value) in self.siblings.iter().zip(witness.siblings.iter()) {
            pw.set_hash_target(*ht, *value);
        }
        for (t, lr_bit) in self.index.iter().zip(index.iter()) {
            pw.set_bool_target(*t, *lr_bit);
        }
        self.old_leaf_data.set_witness(pw, witness.old_leaf_data);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeOutputProcessProof<F: RichField, H: Hasher<F>, K: KeyLike> {
    siblings: Vec<H::Hash>,
    index: K,
    new_leaf_data: Asset<F>,
}

#[derive(Clone, Debug)]
pub struct PurgeOutputProcessProofTarget {
    siblings: Vec<HashOutTarget>,
    index: Vec<BoolTarget>,
    new_leaf_data: AssetTarget,
}

impl PurgeOutputProcessProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_n_kinds: usize,
    ) -> Self {
        let siblings = builder.add_virtual_hashes(log_n_kinds);
        let index = (0..log_n_kinds)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();
        let new_leaf_data = AssetTarget {
            contract_address: builder.add_virtual_hash(),
            token_id: builder.add_virtual_hash(),
            amount: builder.add_virtual_target(),
        };

        Self {
            siblings,
            index,
            new_leaf_data,
        }
    }

    pub fn set_witness<F: RichField, H: Hasher<F, Hash = HashOut<F>>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &PurgeOutputProcessProof<F, H, K>,
    ) {
        // let { w1, index, new_leaf_data} = witness;
        // assert_eq!(w0.old_root, prev_diff_root);
        // prev_diff_root = w0.new_root;

        // assert!(
        //     w0.fnc == ProcessMerkleProofRole::ProcessUpdate
        //         || w0.fnc == ProcessMerkleProofRole::ProcessInsert
        // );

        let index = witness.index.to_bits();
        let mut w1_old_root = H::hash_or_noop(&encode_asset(&Asset::default()));
        let mut w1_new_root = H::hash_or_noop(&encode_asset(&witness.new_leaf_data));
        assert_eq!(index.len(), witness.siblings.len());
        for (lr_bit, sibling) in index.iter().zip(witness.siblings.iter()) {
            if *lr_bit {
                w1_old_root = H::two_to_one(*sibling, w1_old_root);
                w1_new_root = H::two_to_one(*sibling, w1_new_root);
            } else {
                w1_old_root = H::two_to_one(w1_old_root, *sibling);
                w1_new_root = H::two_to_one(w1_new_root, *sibling);
            }
        }

        // verify_layered_smt_connection(
        //     w0.fnc,
        //     w0.old_value,
        //     w0.new_value,
        //     w1_old_root.into(),
        //     w1_new_root.into(),
        // )
        // .unwrap_or_else(|_| {
        //     panic!(
        //         "invalid connection between first and second SMT proof of index {} in output witnesses",
        //         i
        //     )
        // });
        // assert!(
        //     w1.fnc == ProcessMerkleProofRole::ProcessUpdate
        //         || w1.fnc == ProcessMerkleProofRole::ProcessInsert
        // );
        // verify_layered_smt_connection(
        //     w1.fnc,
        //     w1.old_value,
        //     w1.new_value,
        //     w2.old_root,
        //     w2.new_root,
        // )
        // .unwrap_or_else(|_| {
        //     panic!(
        //         "invalid connection between second and third SMT proof of index {} in output witnesses",
        //         i
        //     )
        // });
        // assert_eq!(w2.fnc, ProcessMerkleProofRole::ProcessInsert);
        // assert!(w2.old_value.elements[0].to_canonical_u64() < 1u64 << 56);
        // assert_eq!(w2.old_value.elements[1], F::ZERO);
        // assert_eq!(w2.old_value.elements[2], F::ZERO);
        // assert_eq!(w2.old_value.elements[3], F::ZERO);
        assert!(witness.new_leaf_data.amount < 1u64 << 56);

        // p0_t.set_witness(pw, w0);
        for (ht, value) in self.siblings.iter().zip(witness.siblings.iter()) {
            pw.set_hash_target(*ht, *value);
        }
        for (t, lr_bit) in self.index.iter().zip(index.iter()) {
            pw.set_bool_target(*t, *lr_bit);
        }
        self.new_leaf_data.set_witness(pw, witness.new_leaf_data);
    }
}

#[derive(Clone, Debug)]
pub struct PurgeTransitionTarget {
    pub sender_address: AddressTarget,                     // input
    pub input_proofs: Vec<PurgeInputProcessProofTarget>,   // input
    pub output_proofs: Vec<PurgeOutputProcessProofTarget>, // input
    pub old_user_asset_root: HashOutTarget,                // input
    pub new_user_asset_root: HashOutTarget,                // output
    pub diff_root: HashOutTarget,                          // output

    /// tx_hash が被らないようにするための値.
    pub nonce: HashOutTarget, // input

    /// `hash(diff_root, nonce)` で計算される transaction ごとに unique な値
    /// NOTICE: deposit の場合は計算方法が異なる.
    pub tx_hash: HashOutTarget, // output

    pub log_max_n_txs: usize,       // constant
    pub log_max_n_contracts: usize, // constant
    pub log_max_n_variables: usize, // constant
    pub log_n_recipients: usize,    // constant
    pub log_n_contracts: usize,     // constant
    pub log_n_variables: usize,     // constant
}

impl PurgeTransitionTarget {
    #[allow(clippy::too_many_arguments)]
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_txs: usize,
        log_max_n_contracts: usize,
        log_max_n_variables: usize,
        log_n_recipients: usize,
        log_n_contracts: usize,
        log_n_variables: usize,
        n_diffs: usize,
    ) -> Self {
        let sender_address = AddressTarget::add_virtual_to(builder);
        let old_user_asset_root = builder.add_virtual_hash();
        let nonce = builder.add_virtual_hash();
        let input_proofs_t = (0..n_diffs)
            .map(|_| {
                PurgeInputProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_max_n_contracts + log_max_n_variables,
                )
            })
            .collect::<Vec<_>>();

        let output_proofs_t = (0..n_diffs)
            .map(|_| {
                PurgeOutputProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_n_contracts + log_n_variables,
                )
            })
            .collect::<Vec<_>>();

        let (new_user_asset_root, diff_root, tx_hash) = verify_user_asset_purge_proof::<F, H, D>(
            builder,
            &input_proofs_t,
            &output_proofs_t,
            old_user_asset_root,
            nonce,
        );

        Self {
            sender_address,
            input_proofs: input_proofs_t,
            output_proofs: output_proofs_t,
            old_user_asset_root,
            new_user_asset_root,
            diff_root,
            nonce,
            tx_hash,
            log_max_n_txs,
            log_max_n_contracts,
            log_max_n_variables,
            log_n_recipients,
            log_n_contracts,
            log_n_variables,
        }
    }

    /// Returns (new_user_asset_root, tx_diff_root)
    pub fn set_witness<F: RichField, H: Hasher<F, Hash = HashOut<F>>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        sender_address: Address<F>,
        input_witness: &[PurgeInputProcessProof<F, H, K>],
        output_witness: &[PurgeOutputProcessProof<F, H, K>],
        old_user_asset_root: WrappedHashOut<F>,
        nonce: WrappedHashOut<F>,
    ) -> (WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>) {
        self.sender_address.set_witness(pw, sender_address);
        pw.set_hash_target(self.old_user_asset_root, *old_user_asset_root);
        pw.set_hash_target(self.nonce, *nonce);
        assert!(input_witness.len() <= self.input_proofs.len());
        let prev_user_asset_root = old_user_asset_root;
        for (input_witness_t, input_witness) in self.input_proofs.iter().zip(input_witness.iter()) {
            input_witness_t.set_witness(pw, input_witness);
        }
        let new_user_asset_root = prev_user_asset_root;

        let default_asset_tree = SparseMerkleTreeMemory::<F, H>::new(
            self.log_max_n_contracts + self.log_max_n_variables,
            HashOut::ZERO.elements.to_vec(),
        );
        let default_merkle_proof = default_asset_tree.prove(&vec![
            false;
            self.log_max_n_contracts
                + self.log_max_n_variables
        ]);
        let default_leaf_data = Asset::default();

        for input_proof_t in self.input_proofs.iter().skip(input_witness.len()) {
            input_proof_t.set_witness::<F, H, Vec<bool>>(
                pw,
                &PurgeInputProcessProof {
                    siblings: default_merkle_proof.siblings.clone(),
                    index: input_proof_t
                        .index
                        .iter()
                        .map(|_| false)
                        .collect::<Vec<_>>(),
                    old_leaf_data: default_leaf_data,
                },
            );
        }

        assert!(output_witness.len() <= self.output_proofs.len());
        let prev_diff_root = WrappedHashOut::default();
        for (output_proof_t, output_proof) in self.output_proofs.iter().zip(output_witness.iter()) {
            output_proof_t.set_witness(pw, output_proof);
        }
        let diff_root = prev_diff_root;

        for output_proof_t in self.output_proofs.iter().skip(output_witness.len()) {
            output_proof_t.set_witness::<F, H, Vec<bool>>(
                pw,
                &PurgeOutputProcessProof {
                    siblings: default_merkle_proof.siblings.clone(),
                    index: output_proof_t
                        .index
                        .iter()
                        .map(|_| false)
                        .collect::<Vec<_>>(),
                    new_leaf_data: default_leaf_data,
                },
            );
        }

        let tx_hash = PoseidonHash::two_to_one(*diff_root, *nonce).into();

        (new_user_asset_root, diff_root, tx_hash)
    }
}

// Returns (`new_user_asset_root`, `tx_hash`)
pub fn verify_user_asset_purge_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    input_proofs_t: &[PurgeInputProcessProofTarget],
    output_proofs_t: &[PurgeOutputProcessProofTarget],
    old_user_asset_root: HashOutTarget,
    nonce: HashOutTarget,
) -> (HashOutTarget, HashOutTarget, HashOutTarget) {
    let constant_true = builder.constant_bool(true);
    let constant_false = builder.constant_bool(false);
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    let default_asset_target = AssetTarget::add_constant_default(builder);
    let default_leaf_hash = builder.hash_n_to_hash_no_pad::<H>(default_asset_target.encode());
    assert_eq!(input_proofs_t.len(), output_proofs_t.len());
    let mut input_assets_t = Vec::with_capacity(input_proofs_t.len());
    let mut prev_user_asset_root = old_user_asset_root;
    for PurgeInputProcessProofTarget {
        siblings: siblings_t,
        index: index_t,
        old_leaf_data: old_leaf_data_t,
    } in input_proofs_t
    {
        let mut proof1_old_root_t = builder.hash_n_to_hash_no_pad::<H>(old_leaf_data_t.encode());
        let mut proof1_new_root_t = default_leaf_hash;
        for (lr_bit, sibling) in index_t.iter().zip(siblings_t) {
            let (l, r) = conditionally_reverse(builder, proof1_old_root_t, *sibling, *lr_bit);
            proof1_old_root_t = poseidon_two_to_one::<F, H, D>(builder, l, r);
            let (l, r) = conditionally_reverse(builder, proof1_new_root_t, *sibling, *lr_bit);
            proof1_new_root_t = poseidon_two_to_one::<F, H, D>(builder, l, r);
        }

        builder.connect_hashes(prev_user_asset_root, proof1_old_root_t);

        prev_user_asset_root = proof1_new_root_t;

        // let is_no_op = get_process_merkle_proof_role(builder, proof0_t.fnc).is_no_op;
        // let merge_key = proof0_t.new_key;
        // let old_root_with_nonce =
        //     poseidon_two_to_one::<F, H, D>(builder, proof1_old_root_t, merge_key);
        // let old_root_with_nonce =
        //     conditionally_select(builder, default_hash, old_root_with_nonce, is_no_op);
        // let new_root_with_nonce =
        //     poseidon_two_to_one::<F, H, D>(builder, proof1_new_root_t, merge_key);
        // let new_root_with_nonce =
        //     conditionally_select(builder, default_hash, new_root_with_nonce, is_no_op);
        // verify_layered_smt_target_connection::<F, D>(
        //     builder,
        //     proof0_t.fnc,
        //     proof0_t.old_value,
        //     proof0_t.new_value,
        //     old_root_with_nonce,
        //     new_root_with_nonce,
        // );

        // verify_layered_smt_target_connection::<F, D>(
        //     builder,
        //     proof1_t.fnc,
        //     proof1_t.old_value,
        //     proof1_t.new_value,
        //     proof2_t.old_root,
        //     proof2_t.new_root,
        // );

        // // proof2_t.fnc が ProcessDeleteOp または ProcessNoOp であること
        // let is_not_remove_op = logical_xor(builder, proof2_t.fnc[0], proof2_t.fnc[1]);
        // // let is_not_remove_op =
        // //     get_process_merkle_proof_role(builder, proof2_t.fnc).is_insert_or_update_op;
        // // builder.connect(is_not_remove_op.target, constant_false.target); // XXX: row 453

        // // proof2_t.old_value (取り除いた asset) が 2^56 未満の値であること
        // builder.range_check(proof2_t.old_value.elements[0], 56);
        // builder.connect(proof2_t.old_value.elements[1], zero);
        // builder.connect(proof2_t.old_value.elements[2], zero);
        // builder.connect(proof2_t.old_value.elements[3], zero);
        builder.range_check(old_leaf_data_t.amount, 56);

        input_assets_t.push(*old_leaf_data_t);
    }
    let new_user_asset_root = prev_user_asset_root;

    let mut prev_diff_root = default_hash;
    let mut output_assets_t = Vec::with_capacity(output_proofs_t.len());
    for PurgeOutputProcessProofTarget {
        siblings: siblings_t,
        index: index_t,
        new_leaf_data: new_leaf_data_t,
    } in output_proofs_t
    {
        let mut proof1_old_root_t = default_leaf_hash;
        let mut proof1_new_root_t = builder.hash_n_to_hash_no_pad::<H>(new_leaf_data_t.encode());
        for (lr_bit, sibling) in index_t.iter().zip(siblings_t) {
            let (l, r) = conditionally_reverse(builder, proof1_old_root_t, *sibling, *lr_bit);
            proof1_old_root_t = poseidon_two_to_one::<F, H, D>(builder, l, r);
            let (l, r) = conditionally_reverse(builder, proof1_new_root_t, *sibling, *lr_bit);
            proof1_new_root_t = poseidon_two_to_one::<F, H, D>(builder, l, r);
        }
        builder.connect_hashes(prev_diff_root, proof1_old_root_t);

        prev_diff_root = proof1_new_root_t;

        // verify_layered_smt_target_connection::<F, D>(
        //     builder,
        //     proof0_t.fnc,
        //     proof0_t.old_value,
        //     proof0_t.new_value,
        //     proof1_old_root_t,
        //     proof1_new_root_t,
        // );

        // verify_layered_smt_target_connection::<F, D>(
        //     builder,
        //     proof1_t.fnc,
        //     proof1_t.old_value,
        //     proof1_t.new_value,
        //     proof2_t.old_root,
        //     proof2_t.new_root,
        // );

        // // proof2_t.fnc が ProcessInsertOp または ProcessNoOp であること
        // let is_insert_op = builder.not(proof2_t.fnc[1]);
        // builder.connect(is_insert_op.target, constant_true.target);

        // // proof2_t.new_value が 2^56 未満の値であること
        // builder.range_check(proof2_t.new_value.elements[0], 56);
        // builder.connect(proof2_t.new_value.elements[1], zero);
        // builder.connect(proof2_t.new_value.elements[2], zero);
        // builder.connect(proof2_t.new_value.elements[3], zero);
        builder.range_check(new_leaf_data_t.amount, 56);

        output_assets_t.push(*new_leaf_data_t);
    }
    let diff_root = prev_diff_root;

    verify_equal_assets::<F, H, D>(builder, &input_assets_t, &output_assets_t);

    let tx_hash = poseidon_two_to_one::<F, H, D>(builder, diff_root, nonce);

    (new_user_asset_root, diff_root, tx_hash)
}

#[test]
fn test_purge_proof_by_plonky2() {
    use std::time::Instant;

    use plonky2::{
        field::types::Field,
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        sparse_merkle_tree::goldilocks_poseidon::{
            GoldilocksHashOut, NodeDataMemory, PoseidonSparseMerkleTree, RootDataTmp,
            WrappedHashOut,
        },
        transaction::{
            asset::{Asset, TokenKind},
            tree::{tx_diff::TxDiffTree, user_asset::UserAssetTree},
        },
        zkdsa::account::{private_key_to_account, Address},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const LOG_MAX_N_TXS: usize = 3;
    const LOG_MAX_N_CONTRACTS: usize = 3;
    const LOG_MAX_N_VARIABLES: usize = 3;
    const LOG_N_RECIPIENTS: usize = 3;
    const LOG_N_CONTRACTS: usize = 3;
    const LOG_N_VARIABLES: usize = 3;
    const N_DIFFS: usize = 2;

    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let target = PurgeTransitionTarget::add_virtual_to::<F, H, D>(
        &mut builder,
        LOG_MAX_N_TXS,
        LOG_MAX_N_CONTRACTS,
        LOG_MAX_N_VARIABLES,
        LOG_N_RECIPIENTS,
        LOG_N_CONTRACTS,
        LOG_N_VARIABLES,
        N_DIFFS,
    );
    builder.register_public_inputs(&target.new_user_asset_root.elements);
    builder.register_public_inputs(&target.diff_root.elements);
    builder.register_public_inputs(&target.tx_hash.elements);
    let data = builder.build::<C>();

    // dbg!(&data.common);

    let merge_key1 = GoldilocksHashOut::from_u128(1);
    let asset1 = Asset {
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(3).0),
            variable_index: 8u8.into(),
        },
        amount: 2,
    };
    let merge_key2 = GoldilocksHashOut::from_u128(12);
    let asset2 = Asset {
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(4).0),
            variable_index: 8u8.into(),
        },
        amount: 1,
    };

    let recipient3 = Address(GoldilocksHashOut::from_u128(407).0);
    let asset3 = Asset {
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(3).0),
            variable_index: 8u8.into(),
        },
        amount: 2,
    };
    let recipient4 = Address(GoldilocksHashOut::from_u128(832).0);
    let asset4 = Asset {
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(4).0),
            variable_index: 8u8.into(),
        },
        amount: 1,
    };

    let private_key = HashOut {
        elements: [
            F::from_canonical_u64(15657143458229430356),
            F::from_canonical_u64(6012455030006979790),
            F::from_canonical_u64(4280058849535143691),
            F::from_canonical_u64(5153662694263190591),
        ],
    };
    let user_account = private_key_to_account(private_key);
    let user_address = user_account.address;

    let mut world_state_tree =
        PoseidonSparseMerkleTree::new(NodeDataMemory::default(), RootDataTmp::default());

    let mut user_asset_tree =
        UserAssetTree::<F, H>::new(LOG_MAX_N_TXS, LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);
    let mut tx_diff_tree =
        TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);

    user_asset_tree
        .insert_assets(merge_key1, user_address, vec![asset1])
        .unwrap();
    user_asset_tree
        .insert_assets(merge_key2, user_address, vec![asset2])
        .unwrap();

    world_state_tree
        .set(
            user_address.to_hash_out().into(),
            user_asset_tree.get_root().unwrap().into(),
        )
        .unwrap();

    let old_user_asset_root = user_asset_tree.get_root().unwrap();
    let old_leaf_data1 = user_asset_tree.remove(&merge_key2, &asset2.kind).unwrap();
    let proof1 = user_asset_tree
        .prove_leaf_node(&merge_key2, &asset2.kind)
        .unwrap();
    let old_leaf_data2 = user_asset_tree.remove(&merge_key1, &asset1.kind).unwrap();
    let proof2 = user_asset_tree
        .prove_leaf_node(&merge_key1, &asset1.kind)
        .unwrap();

    tx_diff_tree.insert(recipient3, asset3).unwrap();
    let proof3 = tx_diff_tree
        .prove_leaf_node(&recipient3, &asset3.kind)
        .unwrap();
    tx_diff_tree.insert(recipient4, asset4).unwrap();
    let proof4 = tx_diff_tree
        .prove_leaf_node(&recipient4, &asset3.kind)
        .unwrap();

    let input_witness = vec![
        PurgeInputProcessProof {
            siblings: proof1.siblings,
            index: proof1.index,
            old_leaf_data: old_leaf_data1,
        },
        PurgeInputProcessProof {
            siblings: proof2.siblings,
            index: proof2.index,
            old_leaf_data: old_leaf_data2,
        },
    ];
    let output_witness = vec![
        PurgeOutputProcessProof {
            siblings: proof3.siblings,
            index: proof3.index,
            new_leaf_data: asset3,
        },
        PurgeOutputProcessProof {
            siblings: proof4.siblings,
            index: proof4.index,
            new_leaf_data: asset4,
        },
    ];
    let nonce = WrappedHashOut::from(HashOut {
        elements: [
            F::from_canonical_u64(6657881311364026367),
            F::from_canonical_u64(11761473381903976612),
            F::from_canonical_u64(10768494808833234712),
            F::from_canonical_u64(3223267375194257474),
        ],
    });

    let mut pw = PartialWitness::new();
    target.set_witness::<F, H, HashOut<F>>(
        &mut pw,
        user_address,
        &input_witness,
        &output_witness,
        old_user_asset_root.into(),
        nonce,
    );

    println!("start proving: proof");
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }

    let mut pw = PartialWitness::new();
    target.set_witness::<F, H, HashOut<F>>(
        &mut pw,
        Default::default(),
        &[],
        &[],
        Default::default(),
        Default::default(),
    );

    println!("start proving: default_proof");
    let start = Instant::now();
    let default_proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match data.verify(default_proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
