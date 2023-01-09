use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use crate::{
    poseidon::gadgets::poseidon_two_to_one,
    sparse_merkle_tree::{
        gadgets::{
            common::{conditionally_select, logical_xor},
            process::{
                process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
                utils::{get_process_merkle_proof_role, verify_layered_smt_target_connection},
            },
        },
        goldilocks_poseidon::WrappedHashOut,
        layered_tree::verify_layered_smt_connection,
        proof::ProcessMerkleProofRole,
    },
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

use super::asset_mess::{verify_equal_assets, AssetTargets};

#[derive(Clone, Debug)]
pub struct PurgeTransitionTarget {
    pub sender_address: AddressTarget, // input
    pub input_proofs: Vec<(
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
    )>, // input
    pub output_proofs: Vec<(
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
    )>, // input
    pub old_user_asset_root: HashOutTarget, // input
    pub new_user_asset_root: HashOutTarget, // output
    pub diff_root: HashOutTarget,      // output

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
                let proof0_t = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_max_n_txs,
                );
                let proof1_t = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_max_n_contracts,
                );
                let proof2_t = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_max_n_variables,
                );
                (proof0_t, proof1_t, proof2_t)
            })
            .collect::<Vec<_>>();

        let output_proofs_t = (0..n_diffs)
            .map(|_| {
                let proof0_t = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_n_recipients,
                );
                let proof1_t = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_n_contracts,
                );
                let proof2_t = SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_n_variables,
                );
                (proof0_t, proof1_t, proof2_t)
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
    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        sender_address: Address<F>,
        input_witness: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
        output_witness: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
        old_user_asset_root: WrappedHashOut<F>,
        nonce: WrappedHashOut<F>,
    ) -> (WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>) {
        self.sender_address.set_witness(pw, sender_address);
        pw.set_hash_target(self.old_user_asset_root, *old_user_asset_root);
        pw.set_hash_target(self.nonce, *nonce);
        assert!(input_witness.len() <= self.input_proofs.len());
        let mut prev_user_asset_root = old_user_asset_root;
        for (i, ((p0_t, p1_t, p2_t), (w0, w1, w2))) in self
            .input_proofs
            .iter()
            .zip(input_witness.iter())
            .enumerate()
        {
            assert_eq!(w0.old_root, prev_user_asset_root);
            prev_user_asset_root = w0.new_root;

            let merge_key = w0.new_key;
            let old_root_with_nonce = PoseidonHash::two_to_one(*w1.old_root, *merge_key).into();
            let new_root_with_nonce = PoseidonHash::two_to_one(*w1.new_root, *merge_key).into();
            assert_eq!(w0.fnc, ProcessMerkleProofRole::ProcessUpdate);
            verify_layered_smt_connection(
                w0.fnc,
                w0.old_value,
                w0.new_value,
                old_root_with_nonce,
                new_root_with_nonce,
            )
            .unwrap_or_else(|_| {
                panic!(
                    "invalid connection between first and second SMT proof of index {} in input witnesses",
                    i
                )
            }); // XXX
            assert!(
                w1.fnc == ProcessMerkleProofRole::ProcessUpdate
                    || w1.fnc == ProcessMerkleProofRole::ProcessDelete
            );
            verify_layered_smt_connection(
                w1.fnc,
                w1.old_value,
                w1.new_value,
                w2.old_root,
                w2.new_root,
            )
            .unwrap_or_else(|_| {
                panic!(
                    "invalid connection between second and third SMT proof of index {} in input witnesses",
                    i
                )
            });
            assert_eq!(w2.fnc, ProcessMerkleProofRole::ProcessDelete);
            assert!(w2.old_value.elements[0].to_canonical_u64() < 1u64 << 56);
            assert_eq!(w2.old_value.elements[1], F::ZERO);
            assert_eq!(w2.old_value.elements[2], F::ZERO);
            assert_eq!(w2.old_value.elements[3], F::ZERO);

            p0_t.set_witness(pw, w0);
            p1_t.set_witness(pw, w1);
            p2_t.set_witness(pw, w2);
        }
        let new_user_asset_root = prev_user_asset_root;

        let default_witness0 = SmtProcessProof::with_root(new_user_asset_root);
        let default_witness1 = SmtProcessProof::with_root(Default::default());
        let default_witness2 = SmtProcessProof::with_root(Default::default());

        for (p0_t, p1_t, p2_t) in self.input_proofs.iter().skip(input_witness.len()) {
            p0_t.set_witness(pw, &default_witness0);
            p1_t.set_witness(pw, &default_witness1);
            p2_t.set_witness(pw, &default_witness2);
        }

        assert!(output_witness.len() <= self.output_proofs.len());
        let mut prev_diff_root = WrappedHashOut::default();
        for (i, ((p0_t, p1_t, p2_t), (w0, w1, w2))) in self
            .output_proofs
            .iter()
            .zip(output_witness.iter())
            .enumerate()
        {
            assert_eq!(w0.old_root, prev_diff_root);
            prev_diff_root = w0.new_root;

            assert!(
                w0.fnc == ProcessMerkleProofRole::ProcessUpdate
                    || w0.fnc == ProcessMerkleProofRole::ProcessInsert
            );
            verify_layered_smt_connection(
                w0.fnc,
                w0.old_value,
                w0.new_value,
                w1.old_root,
                w1.new_root,
            )
            .unwrap_or_else(|_| {
                panic!(
                    "invalid connection between first and second SMT proof of index {} in output witnesses",
                    i
                )
            });
            assert!(
                w1.fnc == ProcessMerkleProofRole::ProcessUpdate
                    || w1.fnc == ProcessMerkleProofRole::ProcessInsert
            );
            verify_layered_smt_connection(
                w1.fnc,
                w1.old_value,
                w1.new_value,
                w2.old_root,
                w2.new_root,
            )
            .unwrap_or_else(|_| {
                panic!(
                    "invalid connection between second and third SMT proof of index {} in output witnesses",
                    i
                )
            });
            assert_eq!(w2.fnc, ProcessMerkleProofRole::ProcessInsert);
            assert!(w2.old_value.elements[0].to_canonical_u64() < 1u64 << 56);
            assert_eq!(w2.old_value.elements[1], F::ZERO);
            assert_eq!(w2.old_value.elements[2], F::ZERO);
            assert_eq!(w2.old_value.elements[3], F::ZERO);
            p0_t.set_witness(pw, w0);
            p1_t.set_witness(pw, w1);
            p2_t.set_witness(pw, w2);
        }
        let diff_root = prev_diff_root;

        let default_witness0 = SmtProcessProof::with_root(diff_root);
        let default_witness1 = SmtProcessProof::with_root(Default::default());
        let default_witness2 = SmtProcessProof::with_root(Default::default());

        for (p0_t, p1_t, p2_t) in self.output_proofs.iter().skip(output_witness.len()) {
            p0_t.set_witness(pw, &default_witness0);
            p1_t.set_witness(pw, &default_witness1);
            p2_t.set_witness(pw, &default_witness2);
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
    input_proofs_t: &[(
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
    )],
    output_proofs_t: &[(
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
        SparseMerkleProcessProofTarget,
    )],
    old_user_asset_root: HashOutTarget,
    nonce: HashOutTarget,
) -> (HashOutTarget, HashOutTarget, HashOutTarget) {
    let constant_true = builder.constant_bool(true);
    let constant_false = builder.constant_bool(false);
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    assert_eq!(input_proofs_t.len(), output_proofs_t.len());
    let mut input_assets_t = Vec::with_capacity(input_proofs_t.len());
    for (proof0_t, proof1_t, proof2_t) in input_proofs_t {
        let is_no_op = get_process_merkle_proof_role(builder, proof0_t.fnc).is_no_op;
        let merge_key = proof0_t.new_key;
        let old_root_with_nonce =
            poseidon_two_to_one::<F, H, D>(builder, proof1_t.old_root, merge_key);
        let old_root_with_nonce =
            conditionally_select(builder, default_hash, old_root_with_nonce, is_no_op);
        let new_root_with_nonce =
            poseidon_two_to_one::<F, H, D>(builder, proof1_t.new_root, merge_key);
        let new_root_with_nonce =
            conditionally_select(builder, default_hash, new_root_with_nonce, is_no_op);
        verify_layered_smt_target_connection::<F, D>(
            builder,
            proof0_t.fnc,
            proof0_t.old_value,
            proof0_t.new_value,
            old_root_with_nonce,
            new_root_with_nonce,
        );

        verify_layered_smt_target_connection::<F, D>(
            builder,
            proof1_t.fnc,
            proof1_t.old_value,
            proof1_t.new_value,
            proof2_t.old_root,
            proof2_t.new_root,
        );

        // proof2_t.fnc が ProcessDeleteOp または ProcessNoOp であること
        let is_not_remove_op = logical_xor(builder, proof2_t.fnc[0], proof2_t.fnc[1]);
        // let is_not_remove_op =
        //     get_process_merkle_proof_role(builder, proof2_t.fnc).is_insert_or_update_op;
        // builder.connect(is_not_remove_op.target, constant_false.target); // XXX: row 453

        // proof2_t.old_value (取り除いた asset) が 2^56 未満の値であること
        builder.range_check(proof2_t.old_value.elements[0], 56);
        builder.connect(proof2_t.old_value.elements[1], zero);
        builder.connect(proof2_t.old_value.elements[2], zero);
        builder.connect(proof2_t.old_value.elements[3], zero);

        input_assets_t.push(AssetTargets {
            contract_address: proof1_t.old_key,
            token_id: proof2_t.old_key,
            amount: proof2_t.old_value.elements[0],
        });
    }

    let mut prev_user_asset_root = old_user_asset_root;
    for cur_target in input_proofs_t {
        builder.connect_hashes(prev_user_asset_root, cur_target.0.old_root);

        prev_user_asset_root = cur_target.0.new_root;
    }
    let new_user_asset_root = prev_user_asset_root;

    let mut output_assets_t = Vec::with_capacity(output_proofs_t.len());
    for (proof0_t, proof1_t, proof2_t) in output_proofs_t {
        verify_layered_smt_target_connection::<F, D>(
            builder,
            proof0_t.fnc,
            proof0_t.old_value,
            proof0_t.new_value,
            proof1_t.old_root,
            proof1_t.new_root,
        );

        verify_layered_smt_target_connection::<F, D>(
            builder,
            proof1_t.fnc,
            proof1_t.old_value,
            proof1_t.new_value,
            proof2_t.old_root,
            proof2_t.new_root,
        );

        // proof2_t.fnc が ProcessInsertOp または ProcessNoOp であること
        let is_insert_op = builder.not(proof2_t.fnc[1]);
        builder.connect(is_insert_op.target, constant_true.target);

        // proof2_t.new_value が 2^56 未満の値であること
        builder.range_check(proof2_t.new_value.elements[0], 56);
        builder.connect(proof2_t.new_value.elements[1], zero);
        builder.connect(proof2_t.new_value.elements[2], zero);
        builder.connect(proof2_t.new_value.elements[3], zero);

        output_assets_t.push(AssetTargets {
            contract_address: proof1_t.new_key,
            token_id: proof2_t.new_key,
            amount: proof2_t.new_value.elements[0],
        });
    }

    let mut prev_diff_root = default_hash;
    for cur_target in output_proofs_t.iter() {
        builder.connect_hashes(prev_diff_root, cur_target.0.old_root);

        prev_diff_root = cur_target.0.new_root;
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
            GoldilocksHashOut, LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory,
            PoseidonSparseMerkleTree, RootDataTmp,
        },
        transaction::tree::user_asset::UserAssetTree,
        zkdsa::account::private_key_to_account,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const LOG_MAX_N_BLOCKS: usize = 3;
    const LOG_MAX_N_CONTRACTS: usize = 3;
    const LOG_MAX_N_VARIABLES: usize = 3;
    const LOG_N_RECIPIENT: usize = 3;
    const LOG_N_CONTRACTS: usize = 3;
    const LOG_N_VARIABLES: usize = 3;
    const N_DIFFS: usize = 2;

    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let target = PurgeTransitionTarget::add_virtual_to::<F, H, D>(
        &mut builder,
        LOG_MAX_N_BLOCKS,
        LOG_MAX_N_CONTRACTS,
        LOG_MAX_N_VARIABLES,
        LOG_N_RECIPIENT,
        LOG_N_CONTRACTS,
        LOG_N_VARIABLES,
        N_DIFFS,
    );
    builder.register_public_inputs(&target.new_user_asset_root.elements);
    builder.register_public_inputs(&target.diff_root.elements);
    builder.register_public_inputs(&target.tx_hash.elements);
    let data = builder.build::<C>();

    // dbg!(&data.common);

    let key1 = (
        GoldilocksHashOut::from_u128(1),
        GoldilocksHashOut::from_u128(3),
        GoldilocksHashOut::from_u128(8),
    );
    let value1 = GoldilocksHashOut::from_u128(2);
    let key2 = (
        GoldilocksHashOut::from_u128(12),
        GoldilocksHashOut::from_u128(4),
        GoldilocksHashOut::from_u128(8),
    );
    let value2 = GoldilocksHashOut::from_u128(1);

    let key3 = (
        GoldilocksHashOut::from_u128(407),
        GoldilocksHashOut::from_u128(3),
        GoldilocksHashOut::from_u128(8),
    );
    let value3 = GoldilocksHashOut::from_u128(2);
    let key4 = (
        GoldilocksHashOut::from_u128(832),
        GoldilocksHashOut::from_u128(4),
        GoldilocksHashOut::from_u128(8),
    );
    let value4 = GoldilocksHashOut::from_u128(1);

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

    let mut user_asset_tree = UserAssetTree::new(NodeDataMemory::default(), RootDataTmp::default());
    let mut tx_diff_tree = LayeredLayeredPoseidonSparseMerkleTree::new(
        NodeDataMemory::default(),
        RootDataTmp::default(),
    );

    let zero = GoldilocksHashOut::from_u128(0);
    user_asset_tree.set(key1.0, key1.1, key1.2, value1).unwrap();
    user_asset_tree.set(key2.0, key2.1, key2.2, value2).unwrap();

    world_state_tree
        .set(
            user_address.to_hash_out().into(),
            user_asset_tree.get_root().unwrap(),
        )
        .unwrap();

    let proof1 = user_asset_tree.set(key2.0, key2.1, key2.2, zero).unwrap();
    let proof2 = user_asset_tree.set(key1.0, key1.1, key1.2, zero).unwrap();

    let proof3 = tx_diff_tree.set(key3.0, key3.1, key3.2, value3).unwrap();
    let proof4 = tx_diff_tree.set(key4.0, key4.1, key4.2, value4).unwrap();

    let input_witness = vec![proof1, proof2];
    let output_witness = vec![proof3, proof4];
    let nonce = WrappedHashOut::from(HashOut {
        elements: [
            F::from_canonical_u64(6657881311364026367),
            F::from_canonical_u64(11761473381903976612),
            F::from_canonical_u64(10768494808833234712),
            F::from_canonical_u64(3223267375194257474),
        ],
    });

    let mut pw = PartialWitness::new();
    target.set_witness(
        &mut pw,
        user_address,
        &input_witness,
        &output_witness,
        input_witness.first().unwrap().0.old_root,
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
    target.set_witness(
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
