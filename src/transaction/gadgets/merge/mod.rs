use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::{gadgets::MerkleProofTarget, tree::MerkleProof},
    poseidon::gadgets::poseidon_two_to_one,
    sparse_merkle_tree::{
        gadgets::{
            common::{conditionally_select, enforce_equal_if_enabled},
            process::{
                process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
                utils::{get_process_merkle_proof_role, ProcessMerkleProofRoleTarget},
            },
            verify::verify_smt::{SmtInclusionProof, SparseMerkleInclusionProofTarget},
        },
        goldilocks_poseidon::WrappedHashOut,
        proof::ProcessMerkleProofRole,
    },
    transaction::{
        block_header::{get_block_hash, BlockHeader},
        gadgets::block_header::{get_block_hash_target, BlockHeaderTarget},
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    deserialize = "SmtInclusionProof<F>: Deserialize<'de>, SmtProcessProof<F>: Deserialize<'de>, BlockHeader<F>: Deserialize<'de>, MerkleProof<F>: Deserialize<'de>"
))]
pub struct MergeProof<F: RichField> {
    pub is_deposit: bool,
    pub diff_tree_inclusion_proof: (BlockHeader<F>, MerkleProof<F>, SmtInclusionProof<F>),
    pub merge_process_proof: SmtProcessProof<F>,

    /// asset を受け取った block の latest account tree から自身の address に関する inclusion proof を出す
    pub latest_account_tree_inclusion_proof: SmtInclusionProof<F>,

    /// is_deposit が false のとき, 送信者から nonce の値を教えてもらう必要がある
    pub nonce: WrappedHashOut<F>,
}

#[derive(Clone, Debug)]
pub struct MergeProofTarget {
    // pub is_deposit: BoolTarget,
    pub diff_tree_inclusion_proof: (
        BlockHeaderTarget,
        MerkleProofTarget,
        SparseMerkleInclusionProofTarget,
    ),
    pub merge_process_proof: SparseMerkleProcessProofTarget,
    pub latest_account_tree_inclusion_proof: SparseMerkleInclusionProofTarget,
    pub nonce: HashOutTarget,
}

#[derive(Clone, Debug)]
pub struct MergeTransitionTarget {
    pub proofs: Vec<MergeProofTarget>,      // input
    pub old_user_asset_root: HashOutTarget, // input
    pub new_user_asset_root: HashOutTarget, // output
    pub log_max_n_users: usize,             // constant
    pub log_max_n_txs: usize,               // constant
    pub log_n_txs: usize,                   // constant
    pub log_n_recipients: usize,            // constant
}

impl MergeTransitionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_users: usize,
        log_max_n_txs: usize,
        log_n_txs: usize,
        log_n_recipients: usize,
        n_merges: usize,
    ) -> Self {
        let mut proofs = vec![];
        for _ in 0..n_merges {
            let target = MergeProofTarget {
                // is_deposit: builder.add_virtual_bool_target_safe(),
                diff_tree_inclusion_proof: (
                    BlockHeaderTarget::add_virtual_to::<F, D>(builder),
                    MerkleProofTarget::add_virtual_to::<F, H, D>(builder, log_n_txs),
                    SparseMerkleInclusionProofTarget::add_virtual_to::<F, H, D>(
                        builder,
                        log_n_recipients,
                    ),
                ),
                merge_process_proof: SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                    log_max_n_txs,
                ),
                latest_account_tree_inclusion_proof:
                    SparseMerkleInclusionProofTarget::add_virtual_to::<F, H, D>(
                        builder,
                        log_max_n_users,
                    ),
                nonce: builder.add_virtual_hash(),
            };

            proofs.push(target);
        }

        let old_user_asset_root = builder.add_virtual_hash();
        let new_user_asset_root =
            verify_user_asset_merge_proof::<F, H, D>(builder, &proofs, old_user_asset_root);

        Self {
            proofs,
            old_user_asset_root,
            new_user_asset_root,
            log_max_n_users,
            log_max_n_txs,
            log_n_txs,
            log_n_recipients,
        }
    }

    /// Returns new_user_asset_root
    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        proofs: &[MergeProof<F>],
        old_user_asset_root: HashOut<F>,
    ) -> WrappedHashOut<F> {
        pw.set_hash_target(self.old_user_asset_root, old_user_asset_root);

        let first_root = old_user_asset_root.into();
        if let Some(first_witness) = proofs.first() {
            assert_eq!(first_witness.merge_process_proof.old_root, first_root);
        }

        let mut new_user_asset_root = first_root;
        assert!(proofs.len() <= self.proofs.len());
        for (target, witness) in self.proofs.iter().zip(proofs.iter()) {
            assert_ne!(
                witness.merge_process_proof.fnc,
                ProcessMerkleProofRole::ProcessNoOp
            );

            let block_header = &witness.diff_tree_inclusion_proof.0;
            let root = if witness.is_deposit {
                block_header.deposit_digest
            } else {
                block_header.transactions_digest
            };
            assert_eq!(root, *witness.diff_tree_inclusion_proof.1.root);
            let block_hash = get_block_hash(block_header);

            if witness.is_deposit {
                let network_index =
                    F::from_canonical_usize(witness.diff_tree_inclusion_proof.1.index);
                let network_index = HashOut::from_partial(&[network_index]);
                assert_eq!(*witness.nonce, network_index);
            }
            let diff_root = witness.diff_tree_inclusion_proof.2.root;
            let tx_hash = PoseidonHash::two_to_one(*diff_root, *witness.nonce).into();
            assert_eq!(witness.diff_tree_inclusion_proof.1.value, tx_hash);

            let merge_key = if witness.is_deposit {
                // println!("deposit");
                PoseidonHash::two_to_one(*tx_hash, block_hash).into()
            } else {
                // println!("purge");
                tx_hash
            };

            assert_eq!(witness.merge_process_proof.new_key, merge_key);
            assert_eq!(
                witness.merge_process_proof.fnc,
                ProcessMerkleProofRole::ProcessInsert
            );
            let asset_root = witness.diff_tree_inclusion_proof.2.value;
            let asset_root_with_merge_key =
                PoseidonHash::two_to_one(*asset_root, *merge_key).into();
            assert_eq!(
                witness.merge_process_proof.new_value,
                asset_root_with_merge_key
            ); // XXX: test_merge_proof_by_plonky2
            assert_eq!(
                witness.diff_tree_inclusion_proof.0.latest_account_digest,
                *witness.latest_account_tree_inclusion_proof.root,
            ); // XXX
            assert_eq!(witness.merge_process_proof.old_root, new_user_asset_root);

            // transfer のとき, latest_account_tree (active_account_tree) に正しい値が入っていることの検証
            {
                let is_not_no_op =
                    witness.merge_process_proof.fnc != ProcessMerkleProofRole::ProcessNoOp;
                let receiving_block_number = witness.diff_tree_inclusion_proof.0.block_number;
                let confirmed_block_number = witness.latest_account_tree_inclusion_proof.value; // 最後に成功した block number
                if is_not_no_op && !witness.is_deposit {
                    assert_eq!(
                        confirmed_block_number.0,
                        HashOut::from_partial(&[F::from_canonical_u32(receiving_block_number)]),
                    );
                }
            }

            // pw.set_bool_target(target.is_deposit, witness.is_deposit);
            target
                .diff_tree_inclusion_proof
                .0
                .set_witness(pw, &witness.diff_tree_inclusion_proof.0);
            target.diff_tree_inclusion_proof.1.set_witness(
                pw,
                witness.diff_tree_inclusion_proof.1.index,
                witness.diff_tree_inclusion_proof.1.value,
                &witness.diff_tree_inclusion_proof.1.siblings,
            );
            target.diff_tree_inclusion_proof.2.set_witness(
                pw,
                &witness.diff_tree_inclusion_proof.2,
                true,
            );

            target
                .merge_process_proof
                .set_witness(pw, &witness.merge_process_proof);

            // transfer のときのみ検証する
            target.latest_account_tree_inclusion_proof.set_witness(
                pw,
                &witness.latest_account_tree_inclusion_proof,
                !witness.is_deposit,
            );
            pw.set_hash_target(target.nonce, *witness.nonce);

            new_user_asset_root = witness.merge_process_proof.new_root
        }

        let default_header = BlockHeader::new(self.log_n_txs);
        let default_merkle_proof = MerkleProof::new(self.log_n_txs);
        let default_inclusion_proof = SmtInclusionProof::with_root(Default::default());
        let default_process_proof = SmtProcessProof::with_root(new_user_asset_root);
        for target in self.proofs.iter().skip(proofs.len()) {
            // pw.set_bool_target(target.is_deposit, true);
            target
                .diff_tree_inclusion_proof
                .0
                .set_witness(pw, &default_header);
            target.diff_tree_inclusion_proof.1.set_witness(
                pw,
                default_merkle_proof.index,
                default_merkle_proof.value,
                &default_merkle_proof.siblings,
            );
            target
                .diff_tree_inclusion_proof
                .2
                .set_witness(pw, &default_inclusion_proof, false);

            target
                .merge_process_proof
                .set_witness(pw, &default_process_proof);

            target.latest_account_tree_inclusion_proof.set_witness(
                pw,
                &default_inclusion_proof,
                false,
            );
            pw.set_hash_target(target.nonce, HashOut::ZERO);
        }

        new_user_asset_root
    }
}

pub fn verify_user_asset_merge_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    proofs: &[MergeProofTarget],
    old_user_asset_root: HashOutTarget,
) -> HashOutTarget {
    let zero = builder.zero();

    let mut new_user_asset_root = old_user_asset_root;
    for MergeProofTarget {
        // is_deposit: actual_is_deposit,
        merge_process_proof,
        diff_tree_inclusion_proof,
        latest_account_tree_inclusion_proof,
        nonce,
    } in proofs
    {
        let ProcessMerkleProofRoleTarget {
            is_insert_op,
            is_not_no_op,
            ..
        } = get_process_merkle_proof_role::<F, D>(builder, merge_process_proof.fnc);
        let is_transfer = builder.and(latest_account_tree_inclusion_proof.enabled, is_not_no_op);
        let is_not_transfer = builder.not(is_transfer);
        let is_deposit = builder.and(is_not_transfer, is_not_no_op);

        let block_header_t = diff_tree_inclusion_proof.0.clone();

        let root = conditionally_select(
            builder,
            block_header_t.transactions_digest,
            block_header_t.deposit_digest,
            is_transfer,
        );
        // enforce_equal_if_enabled(
        //     builder,
        //     root,
        //     diff_tree_inclusion_proof.1.root,
        //     is_not_no_op,
        // ); // XXX

        let receiving_block_number = diff_tree_inclusion_proof.0.block_number;
        let confirmed_block_number = latest_account_tree_inclusion_proof.value; // 最後に成功した block number

        // transfer のとき, latest_account_tree (active_account_tree) に正しい値が入っていることの検証
        {
            enforce_equal_if_enabled(
                builder,
                confirmed_block_number,
                HashOutTarget::from_partial(&[receiving_block_number], zero),
                is_transfer,
            );
        }

        // deposit のとき, nonce は network_index
        {
            let network_index =
                HashOutTarget::from_partial(&[diff_tree_inclusion_proof.1.index], zero);
            enforce_equal_if_enabled(builder, *nonce, network_index, is_deposit);
        }

        // diff_tree_inclusion_proof.2.root と diff_tree_inclusion_proof.1.value の関係を拘束する
        {
            let inclusion1_proof_value =
                poseidon_two_to_one::<F, H, D>(builder, diff_tree_inclusion_proof.2.root, *nonce);
            enforce_equal_if_enabled(
                builder,
                diff_tree_inclusion_proof.1.value,
                inclusion1_proof_value,
                is_not_no_op,
            );
        }

        // deposit と purge の場合で merge の計算方法が異なる.
        let block_hash = get_block_hash_target::<F, H, D>(builder, &diff_tree_inclusion_proof.0);
        let merge_key = {
            let tx_hash = diff_tree_inclusion_proof.1.value;
            let deposit_merge_key = poseidon_two_to_one::<F, H, D>(builder, tx_hash, block_hash);
            let purge_merge_key = tx_hash;

            conditionally_select(builder, purge_merge_key, deposit_merge_key, is_transfer)
        };

        // enforce_equal_if_enabled(builder, merge_process_proof.new_key, merge_key, is_not_no_op); // XXX

        // noop でないならば insert である
        builder.connect(is_not_no_op.target, is_insert_op.target);

        let asset_root = diff_tree_inclusion_proof.2.value;
        let asset_root_with_merge_key =
            poseidon_two_to_one::<F, H, D>(builder, asset_root, merge_key);
        enforce_equal_if_enabled(
            builder,
            merge_process_proof.new_value,
            asset_root_with_merge_key,
            is_not_no_op,
        );
        enforce_equal_if_enabled(
            builder,
            diff_tree_inclusion_proof.0.latest_account_digest,
            latest_account_tree_inclusion_proof.root,
            is_not_no_op,
        );
        enforce_equal_if_enabled(
            builder,
            merge_process_proof.old_root,
            new_user_asset_root,
            is_not_no_op,
        );

        new_user_asset_root = conditionally_select(
            builder,
            merge_process_proof.new_root,
            new_user_asset_root,
            is_not_no_op,
        );
    }

    // let new_user_asset_root = proofs.last().unwrap().merge_process_proof.new_root;

    new_user_asset_root
}

#[test]
fn test_merge_proof_by_plonky2() {
    use std::time::Instant;

    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        merkle_tree::tree::get_merkle_proof,
        sparse_merkle_tree::{
            goldilocks_poseidon::{
                GoldilocksHashOut, LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory,
                PoseidonSparseMerkleTree, RootDataTmp,
            },
            proof::SparseMerkleInclusionProof,
        },
        transaction::{block_header::BlockHeader, tree::user_asset::UserAssetTree},
        zkdsa::account::private_key_to_account,
    };

    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    pub const LOG_MAX_N_USERS: usize = 3;
    pub const LOG_MAX_N_TXS: usize = 3;
    pub const LOG_N_TXS: usize = 3;
    pub const LOG_N_RECIPIENTS: usize = 3;
    pub const N_MERGES: usize = 3;

    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_target_index = Some(36);

    let merge_proof_target: MergeTransitionTarget = MergeTransitionTarget::add_virtual_to::<F, H, D>(
        &mut builder,
        LOG_MAX_N_USERS,
        LOG_MAX_N_TXS,
        LOG_N_TXS,
        LOG_N_RECIPIENTS,
        N_MERGES,
    );
    builder.register_public_inputs(&merge_proof_target.old_user_asset_root.elements);
    builder.register_public_inputs(&merge_proof_target.new_user_asset_root.elements);
    let data = builder.build::<C>();

    let contract_address1 = GoldilocksHashOut::from_u128(305);
    let variable_index1 = GoldilocksHashOut::from_u128(8012);
    let amount1 = GoldilocksHashOut::from_u128(2053);
    let contract_address2 = GoldilocksHashOut::from_u128(471);
    let variable_index2 = GoldilocksHashOut::from_u128(8012);
    let amount2 = GoldilocksHashOut::from_u128(1111);

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

    let mut user_asset_tree = UserAssetTree::new(NodeDataMemory::default(), RootDataTmp::default());

    let mut deposit_tree = LayeredLayeredPoseidonSparseMerkleTree::new(
        NodeDataMemory::default(),
        RootDataTmp::default(),
    );

    deposit_tree
        .set(
            user_address.to_hash_out().into(),
            contract_address1,
            variable_index1,
            amount1,
        )
        .unwrap();
    deposit_tree
        .set(
            user_address.to_hash_out().into(),
            contract_address2,
            variable_index2,
            amount2,
        )
        .unwrap();

    let deposit_tree: PoseidonSparseMerkleTree<_, _> = deposit_tree.into();

    let merge_inclusion_proof2 = deposit_tree
        .find(&user_address.to_hash_out().into())
        .unwrap();

    let deposit_nonce = HashOut::ZERO;
    // let deposit_tx_hash =
    //     PoseidonHash::two_to_one(*merge_inclusion_proof2.root, deposit_nonce).into();
    let deposit_tx_hash = PoseidonHash::two_to_one(
        *merge_inclusion_proof2.root,
        *GoldilocksHashOut::from_u64(0),
    );
    let scroll_tx_hash = PoseidonHash::two_to_one(HashOut::ZERO, *GoldilocksHashOut::from_u64(1));
    let polygon_tx_hash = PoseidonHash::two_to_one(HashOut::ZERO, *GoldilocksHashOut::from_u64(2));

    let merge_inclusion_proof1 = get_merkle_proof(
        &[
            deposit_tx_hash.into(),
            scroll_tx_hash.into(),
            polygon_tx_hash.into(),
        ],
        0,
        LOG_N_TXS,
    );

    let default_hash = HashOut::ZERO;
    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    let default_merkle_root = get_merkle_proof(&[], 0, LOG_N_TXS).root;
    let prev_block_header = BlockHeader {
        block_number: 1,
        prev_block_hash: default_hash,
        block_headers_digest: default_hash,
        transactions_digest: *default_merkle_root,
        deposit_digest: *merge_inclusion_proof1.root,
        proposed_world_state_digest: default_hash,
        approved_world_state_digest: default_hash,
        latest_account_digest: default_hash,
    };
    let block_hash = get_block_hash(&prev_block_header);

    let deposit_merge_key = PoseidonHash::two_to_one(deposit_tx_hash, block_hash).into();

    // user asset tree に deposit を merge する.
    user_asset_tree
        .set(
            deposit_merge_key,
            contract_address1,
            variable_index1,
            amount1,
        )
        .unwrap();
    user_asset_tree
        .set(
            deposit_merge_key,
            contract_address2,
            variable_index2,
            amount2,
        )
        .unwrap();

    let mut user_asset_tree: PoseidonSparseMerkleTree<_, _> = user_asset_tree.into();
    let asset_root = user_asset_tree.get(&deposit_merge_key).unwrap();
    {
        let given_asset_root =
            PoseidonHash::two_to_one(*merge_inclusion_proof2.value, *deposit_merge_key).into();
        assert_eq!(asset_root, given_asset_root);
    }

    user_asset_tree
        .set(deposit_merge_key, Default::default())
        .unwrap();
    let merge_process_proof = user_asset_tree.set(deposit_merge_key, asset_root).unwrap();

    let merge_proof = MergeProof {
        is_deposit: true,
        diff_tree_inclusion_proof: (
            prev_block_header,
            merge_inclusion_proof1,
            merge_inclusion_proof2,
        ),
        merge_process_proof,
        latest_account_tree_inclusion_proof: default_inclusion_proof,
        nonce: deposit_nonce.into(),
    };

    let mut pw = PartialWitness::new();

    merge_proof_target.set_witness(&mut pw, &[merge_proof], default_hash);

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

    merge_proof_target.set_witness(&mut pw, &[], default_hash);

    println!("start proving: default proof");
    let start = Instant::now();
    let default_proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    match data.verify(default_proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
