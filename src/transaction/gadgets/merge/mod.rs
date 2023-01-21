use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::{
        gadgets::{get_merkle_root_target, MerkleProofTarget},
        tree::{get_merkle_proof_with_zero, KeyLike, MerkleProcessProof, MerkleProof},
    },
    sparse_merkle_tree::gadgets::verify::verify_smt::{
        SmtInclusionProof, SparseMerkleInclusionProofTarget,
    },
    transaction::{
        block_header::{get_block_hash, BlockHeader},
        gadgets::block_header::{get_block_hash_target, BlockHeaderTarget},
    },
    utils::gadgets::{
        common::{
            conditionally_select, enforce_equal_if_enabled, is_equal_hash_out, logical_and_not,
        },
        poseidon::poseidon_two_to_one,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "H::Hash: KeyLike, BlockHeader<F>: Deserialize<'de>"))]
pub struct DiffTreeInclusionProof<F: RichField, H: Hasher<F>> {
    block_header: BlockHeader<F>,
    siblings1: Vec<H::Hash>,
    siblings2: Vec<H::Hash>,
    root1: H::Hash,
    index1: usize,
    value1: H::Hash,
    root2: H::Hash,
    index2: Vec<bool>,
    value2: H::Hash,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeProof<F: RichField, H: Hasher<F>, K: KeyLike> {
    pub is_deposit: bool,
    #[serde(bound(deserialize = "H::Hash: KeyLike, BlockHeader<F>: Deserialize<'de>"))]
    pub diff_tree_inclusion_proof: DiffTreeInclusionProof<F, H>,
    #[serde(bound(
        deserialize = "MerkleProof<F, H, H::Hash>: Deserialize<'de>, K: Deserialize<'de>"
    ))]
    pub merge_process_proof: MerkleProcessProof<F, H, K>,

    /// asset を受け取った block の latest account tree から自身の address に関する inclusion proof を出す
    #[serde(bound(deserialize = "SmtInclusionProof<F>: Deserialize<'de>"))]
    pub latest_account_tree_inclusion_proof: SmtInclusionProof<F>,

    /// is_deposit が false のとき, 送信者から nonce の値を教えてもらう必要がある
    #[serde(bound(deserialize = "H::Hash: Deserialize<'de>"))]
    pub nonce: H::Hash,
}

impl<F: RichField, H: AlgebraicHasher<F>> MergeProof<F, H, HashOut<F>> {
    pub fn new(
        log_max_n_txs: usize,
        log_n_txs: usize,
        log_n_recipients: usize,
        log_n_kinds: usize,
    ) -> Self {
        let zero = H::hash_or_noop(&[F::ZERO; 4]);
        let default_diff_tree_leaf2 =
            get_merkle_proof_with_zero::<F, H>(&[], 0, log_n_kinds, zero).root;
        let default_diff_tree_inclusion_proof2 =
            get_merkle_proof_with_zero::<F, H>(&[], 0, log_n_recipients, default_diff_tree_leaf2);
        let default_diff_tree_inclusion_root2 = default_diff_tree_inclusion_proof2.root;
        let default_diff_tree_inclusion_index2 = Default::default();
        let default_diff_tree_inclusion_value1 =
            H::two_to_one(default_diff_tree_inclusion_root2, Default::default());
        let default_diff_tree_inclusion_proof1 = get_merkle_proof_with_zero::<F, H>(
            &[],
            0,
            log_n_txs,
            default_diff_tree_inclusion_root2,
        );
        let default_diff_tree_inclusion_index1 = Default::default();
        let default_header = BlockHeader::new(log_n_txs);
        let default_merge_inclusion_proof =
            get_merkle_proof_with_zero::<F, H>(&[], 0, log_max_n_txs, zero);
        let default_merge_process_proof = MerkleProcessProof {
            index: HashOut::ZERO,
            siblings: default_merge_inclusion_proof.siblings,
            old_value: default_merge_inclusion_proof.value,
            new_value: default_merge_inclusion_proof.value,
            old_root: default_merge_inclusion_proof.root,
            new_root: default_merge_inclusion_proof.root,
        };
        let default_inclusion_proof = SmtInclusionProof::with_root(Default::default());

        Self {
            is_deposit: true,
            diff_tree_inclusion_proof: DiffTreeInclusionProof {
                block_header: default_header,
                siblings1: default_diff_tree_inclusion_proof1.siblings,
                siblings2: default_diff_tree_inclusion_proof2.siblings,
                root1: default_diff_tree_inclusion_proof1.root,
                index1: default_diff_tree_inclusion_index1,
                value1: default_diff_tree_inclusion_value1,
                root2: default_diff_tree_inclusion_root2,
                index2: default_diff_tree_inclusion_index2,
                value2: default_diff_tree_leaf2,
            },
            merge_process_proof: default_merge_process_proof,
            latest_account_tree_inclusion_proof: default_inclusion_proof,
            nonce: HashOut::ZERO,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MergeProofTarget {
    // pub is_deposit: BoolTarget,
    pub diff_tree_inclusion_proof: (BlockHeaderTarget, MerkleProofTarget, MerkleProofTarget),
    pub merge_process_proof: (MerkleProofTarget, MerkleProofTarget), // (old, new)
    pub latest_account_tree_inclusion_proof: SparseMerkleInclusionProofTarget,
    pub nonce: HashOutTarget,
}

impl MergeProofTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_users: usize,
        log_max_n_txs: usize,
        log_n_txs: usize,
        log_n_recipients: usize,
    ) -> Self {
        let diff_tree_inclusion_proof = (
            BlockHeaderTarget::add_virtual_to::<F, D>(builder),
            MerkleProofTarget::add_virtual_to::<F, H, D>(builder, log_n_txs),
            MerkleProofTarget::add_virtual_to::<F, H, D>(builder, log_n_recipients),
        );

        let merge_process_proof = {
            let old = MerkleProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_txs);
            let new_value = builder.add_virtual_hash();
            let new = MerkleProofTarget {
                index: old.index.clone(),
                value: new_value,
                siblings: old.siblings.clone(),
                root: get_merkle_root_target::<F, H, D>(
                    builder,
                    &old.index,
                    new_value,
                    &old.siblings,
                ),
            };

            (old, new)
        };

        let latest_account_tree_inclusion_proof =
            SparseMerkleInclusionProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_users);

        let nonce = builder.add_virtual_hash();

        let proof = Self {
            // is_deposit: builder.add_virtual_bool_target_safe(),
            diff_tree_inclusion_proof,
            merge_process_proof,
            latest_account_tree_inclusion_proof,
            nonce,
        };
        verify_user_asset_merge_proof::<F, H, D>(builder, &proof);

        proof
    }

    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &MergeProof<F, H, HashOut<F>>,
    ) {
        let old_value_is_zero = witness.merge_process_proof.old_value == HashOut::ZERO;
        let new_value_is_zero = witness.merge_process_proof.new_value == HashOut::ZERO;
        let is_insert_op = old_value_is_zero && !new_value_is_zero;
        let is_no_op = old_value_is_zero && new_value_is_zero;
        // let is_not_no_op = !is_no_op;

        // noop でないならば insert である
        assert_eq!(!is_no_op, is_insert_op);

        let block_header = &witness.diff_tree_inclusion_proof.block_header;
        let root = if witness.is_deposit {
            block_header.deposit_digest
        } else {
            block_header.transactions_digest
        };
        if !is_no_op {
            assert_eq!(root, witness.diff_tree_inclusion_proof.root1);
        }

        // deposit でないとき, latest_account_tree (active_account_tree) に正しい値が入っていることの検証
        if !is_no_op && !witness.is_deposit {
            let receiving_block_number = block_header.block_number;
            let confirmed_block_number = witness.latest_account_tree_inclusion_proof.value; // 最後に成功した block number
            assert_eq!(
                *confirmed_block_number,
                HashOut::from_partial(&[F::from_canonical_u32(receiving_block_number)]),
            );
        }

        // deposit のとき nonce は 0
        if witness.is_deposit {
            assert_eq!(witness.nonce, Default::default());
        };

        // diff_tree_inclusion_proof.2.root と diff_tree_inclusion_proof.1.value の関係を拘束する
        let diff_root = witness.diff_tree_inclusion_proof.root2;
        let tx_hash = H::two_to_one(diff_root, witness.nonce);
        assert_eq!(witness.diff_tree_inclusion_proof.value1, tx_hash);

        // deposit と purge の場合で merge の計算方法が異なる.
        let block_hash = get_block_hash(block_header);
        let merge_key = if witness.is_deposit {
            H::two_to_one(tx_hash, block_hash)
        } else {
            tx_hash
        };

        if !is_no_op {
            assert_eq!(witness.merge_process_proof.index, merge_key);
        } // XXX
        assert_eq!(witness.merge_process_proof.old_value, Default::default());
        let asset_root = witness.diff_tree_inclusion_proof.value2;
        // let asset_root_with_merge_key = H::two_to_one(asset_root, merge_key);
        if !is_no_op {
            assert_eq!(
                witness.merge_process_proof.new_value,
                asset_root // asset_root_with_merge_key
            );

            assert_eq!(
                block_header.latest_account_digest,
                *witness.latest_account_tree_inclusion_proof.root,
            );
        }

        // pw.set_bool_target(target.is_deposit, witness.is_deposit);
        {
            let diff_tree_inclusion_root2 =
                self.diff_tree_inclusion_proof.2.set_witness::<_, H, _>(
                    pw,
                    &witness.diff_tree_inclusion_proof.index2,
                    witness.diff_tree_inclusion_proof.value2,
                    &witness.diff_tree_inclusion_proof.siblings2,
                );
            if !is_no_op {
                assert_eq!(
                    diff_tree_inclusion_root2,
                    witness.diff_tree_inclusion_proof.root2
                );
            }
        }

        {
            let diff_tree_root = self.diff_tree_inclusion_proof.1.set_witness::<_, H, _>(
                pw,
                &witness.diff_tree_inclusion_proof.index1,
                witness.diff_tree_inclusion_proof.value1,
                &witness.diff_tree_inclusion_proof.siblings1,
            );
            if !is_no_op {
                assert_eq!(diff_tree_root, witness.diff_tree_inclusion_proof.root1);
            }
        }

        self.diff_tree_inclusion_proof
            .0
            .set_witness(pw, &witness.diff_tree_inclusion_proof.block_header);

        let _old_root = self.merge_process_proof.0.set_witness::<_, H, _>(
            pw,
            &witness.merge_process_proof.index,
            witness.merge_process_proof.old_value,
            &witness.merge_process_proof.siblings,
        );
        let _new_root = self.merge_process_proof.1.set_witness::<_, H, _>(
            pw,
            &witness.merge_process_proof.index,
            witness.merge_process_proof.new_value,
            &witness.merge_process_proof.siblings,
        );

        // deposit でないときのみ検証する
        self.latest_account_tree_inclusion_proof.set_witness(
            pw,
            &witness.latest_account_tree_inclusion_proof,
            !witness.is_deposit,
        );
        pw.set_hash_target(self.nonce, witness.nonce);
    }
}

pub fn verify_user_asset_merge_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    proof: &MergeProofTarget,
) {
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    let MergeProofTarget {
        // is_deposit: actual_is_deposit,
        merge_process_proof,
        diff_tree_inclusion_proof,
        latest_account_tree_inclusion_proof,
        nonce,
    } = proof;

    let is_not_deposit = latest_account_tree_inclusion_proof.enabled;

    let old_value_is_zero = is_equal_hash_out(builder, merge_process_proof.0.value, default_hash);
    let new_value_is_zero = is_equal_hash_out(builder, merge_process_proof.1.value, default_hash);
    let is_insert_op = logical_and_not(builder, old_value_is_zero, new_value_is_zero);
    let is_no_op = builder.and(old_value_is_zero, new_value_is_zero);
    let is_not_no_op = builder.not(is_no_op);

    // noop でないならば insert である
    builder.connect(is_not_no_op.target, is_insert_op.target);

    let block_header = &diff_tree_inclusion_proof.0;

    let root = conditionally_select(
        builder,
        block_header.transactions_digest,
        block_header.deposit_digest,
        is_not_deposit,
    );
    enforce_equal_if_enabled(
        builder,
        root,
        diff_tree_inclusion_proof.1.root,
        is_not_no_op,
    );

    // deposit でないとき, latest_account_tree (active_account_tree) に正しい値が入っていることの検証
    {
        let receiving_block_number = block_header.block_number;
        let confirmed_block_number = latest_account_tree_inclusion_proof.value; // 最後に成功した block number
        let check_block_number = builder.and(is_not_no_op, is_not_deposit);
        enforce_equal_if_enabled(
            builder,
            confirmed_block_number,
            HashOutTarget::from_partial(&[receiving_block_number], zero),
            check_block_number,
        );
    }

    // deposit のとき, nonce は 0
    {
        let is_deposit = builder.not(is_not_deposit);
        enforce_equal_if_enabled(builder, *nonce, default_hash, is_deposit);
    }

    // diff_tree_inclusion_proof.2.root と diff_tree_inclusion_proof.1.value の関係を拘束する
    {
        let tx_hash =
            poseidon_two_to_one::<F, H, D>(builder, diff_tree_inclusion_proof.2.root, *nonce);
        enforce_equal_if_enabled(
            builder,
            diff_tree_inclusion_proof.1.value,
            tx_hash,
            is_not_no_op,
        );
    }

    // deposit と purge の場合で merge の計算方法が異なる.
    let block_hash = get_block_hash_target::<F, H, D>(builder, &diff_tree_inclusion_proof.0);
    let merge_key = {
        let tx_hash = diff_tree_inclusion_proof.1.value;
        let deposit_merge_key = poseidon_two_to_one::<F, H, D>(builder, tx_hash, block_hash);
        let purge_merge_key = tx_hash;

        conditionally_select(builder, purge_merge_key, deposit_merge_key, is_not_deposit)
    };

    // merge_key を用いて user asset tree を更新していることを確認.
    let merge_process_proof_index = merge_key
        .elements
        .into_iter()
        .flat_map(|e| builder.split_le(e, 64))
        .collect::<Vec<_>>();

    // key の長さ が SMT の深さと同じかより長ければ良い.
    assert!(merge_process_proof_index.len() >= merge_process_proof.1.index.len());
    for (a, b) in merge_process_proof
        .1
        .index
        .iter()
        .zip(merge_process_proof_index.iter())
    {
        enforce_equal_if_enabled(
            builder,
            HashOutTarget::from_partial(&[a.target], zero),
            HashOutTarget::from_partial(&[b.target], zero),
            is_not_no_op,
        ); // TODO: もう少し良い書き方があるかもしれない.
    }

    let asset_root = diff_tree_inclusion_proof.2.value;
    // let asset_root_with_merge_key = poseidon_two_to_one::<F, H, D>(builder, asset_root, merge_key);
    enforce_equal_if_enabled(
        builder,
        merge_process_proof.1.value,
        asset_root, // asset_root_with_merge_key,
        is_not_no_op,
    );

    enforce_equal_if_enabled(
        builder,
        block_header.latest_account_digest,
        latest_account_tree_inclusion_proof.root,
        is_not_no_op,
    );
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
    pub log_n_kinds: usize,                 // constant
}

impl MergeTransitionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_users: usize,
        log_max_n_txs: usize,
        log_n_txs: usize,
        log_n_recipients: usize,
        log_n_kinds: usize,
        n_merges: usize,
    ) -> Self {
        let mut proofs = vec![];
        for _ in 0..n_merges {
            proofs.push(MergeProofTarget::add_virtual_to::<F, H, D>(
                builder,
                log_max_n_users,
                log_max_n_txs,
                log_n_txs,
                log_n_recipients,
            ));
        }

        let old_user_asset_root = builder.add_virtual_hash();
        let new_user_asset_root =
            verify_user_asset_merge_transitions::<F, H, D>(builder, &proofs, old_user_asset_root);

        Self {
            proofs,
            old_user_asset_root,
            new_user_asset_root,
            log_max_n_users,
            log_max_n_txs,
            log_n_txs,
            log_n_recipients,
            log_n_kinds,
        }
    }

    /// Returns new_user_asset_root
    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        proofs: &[MergeProof<F, H, HashOut<F>>],
        old_user_asset_root: HashOut<F>,
    ) -> HashOut<F> {
        pw.set_hash_target(self.old_user_asset_root, old_user_asset_root);

        let mut new_user_asset_root = old_user_asset_root;
        assert!(proofs.len() <= self.proofs.len());
        for (target, witness) in self.proofs.iter().zip(proofs.iter()) {
            assert_eq!(witness.merge_process_proof.old_root, new_user_asset_root);

            target.set_witness::<F, H>(pw, witness);

            new_user_asset_root = witness.merge_process_proof.new_root
        }

        let default_merge_witness = MergeProof::new(
            self.log_max_n_txs,
            self.log_n_txs,
            self.log_n_recipients,
            self.log_n_kinds,
        );
        for target in self.proofs.iter().skip(proofs.len()) {
            target.set_witness::<F, H>(pw, &default_merge_witness);
        }

        new_user_asset_root
    }
}

pub fn verify_user_asset_merge_transitions<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    proofs: &[MergeProofTarget],
    old_user_asset_root: HashOutTarget,
) -> HashOutTarget {
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    let mut new_user_asset_root = old_user_asset_root;
    for proof in proofs {
        let old_value_is_zero =
            is_equal_hash_out(builder, proof.merge_process_proof.0.value, default_hash);
        let new_value_is_zero =
            is_equal_hash_out(builder, proof.merge_process_proof.1.value, default_hash);
        let is_no_op = builder.and(old_value_is_zero, new_value_is_zero);
        let is_not_no_op = builder.not(is_no_op);

        enforce_equal_if_enabled(
            builder,
            proof.merge_process_proof.0.root,
            new_user_asset_root,
            is_not_no_op,
        );

        new_user_asset_root = conditionally_select(
            builder,
            proof.merge_process_proof.1.root,
            new_user_asset_root,
            is_not_no_op,
        )
    }

    new_user_asset_root
}

#[test]
fn test_two_tree_compatibility() {
    use plonky2::{
        field::types::Field,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use crate::{
        transaction::{
            asset::{ContributedAsset, TokenKind, VariableIndex},
            tree::{tx_diff::TxDiffTree, user_asset::UserAssetTree},
        },
        utils::hash::GoldilocksHashOut,
        zkdsa::account::{private_key_to_account, Address},
    };

    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    const LOG_MAX_N_TXS: usize = 3;
    const LOG_MAX_N_CONTRACTS: usize = 3;
    const LOG_MAX_N_VARIABLES: usize = 3;
    const LOG_N_RECIPIENTS: usize = 3;
    const LOG_N_CONTRACTS: usize = LOG_MAX_N_CONTRACTS;
    const LOG_N_VARIABLES: usize = LOG_MAX_N_VARIABLES;

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

    let asset1 = ContributedAsset {
        receiver_address: user_address,
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(305)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 2053,
    };
    let asset2 = ContributedAsset {
        receiver_address: user_address,
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(471)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 1111,
    };

    let mut user_asset_tree =
        UserAssetTree::<F, H>::new(LOG_MAX_N_TXS, LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);

    let mut deposit_tree =
        TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);

    deposit_tree.insert(asset1).unwrap();
    deposit_tree.insert(asset2).unwrap();

    let diff_tree_inclusion_value2 = deposit_tree.get_asset_root(&user_address).unwrap();

    let deposit_merge_key = HashOut {
        elements: [
            F::from_canonical_u64(10129591887907959457),
            F::from_canonical_u64(12952496368791909874),
            F::from_canonical_u64(5623826813413271961),
            F::from_canonical_u64(13962620032426109816),
        ],
    };

    user_asset_tree
        .insert_assets(deposit_merge_key, vec![asset1, asset2])
        .unwrap();

    // let mut user_asset_tree: UserAssetTree<_, _> = user_asset_tree.into();
    let asset_root = user_asset_tree.get_asset_root(&deposit_merge_key).unwrap();
    {
        assert_eq!(asset_root, diff_tree_inclusion_value2);
    }
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
        sparse_merkle_tree::proof::SparseMerkleInclusionProof,
        transaction::{
            asset::{ContributedAsset, TokenKind, VariableIndex},
            block_header::BlockHeader,
            tree::{tx_diff::TxDiffTree, user_asset::UserAssetTree},
        },
        utils::hash::GoldilocksHashOut,
        zkdsa::account::{private_key_to_account, Address},
    };

    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    const LOG_MAX_N_USERS: usize = 3;
    const LOG_MAX_N_TXS: usize = 3;
    const LOG_MAX_N_CONTRACTS: usize = 3;
    const LOG_MAX_N_VARIABLES: usize = 3;
    const LOG_N_TXS: usize = 3;
    const LOG_N_RECIPIENTS: usize = 3;
    const LOG_N_CONTRACTS: usize = LOG_MAX_N_CONTRACTS;
    const LOG_N_VARIABLES: usize = LOG_MAX_N_VARIABLES;
    const N_MERGES: usize = 3;

    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_target_index = Some(36);

    let merge_proof_target: MergeTransitionTarget = MergeTransitionTarget::add_virtual_to::<F, H, D>(
        &mut builder,
        LOG_MAX_N_USERS,
        LOG_MAX_N_TXS,
        LOG_N_TXS,
        LOG_N_RECIPIENTS,
        LOG_N_CONTRACTS + LOG_N_VARIABLES,
        N_MERGES,
    );
    builder.register_public_inputs(&merge_proof_target.old_user_asset_root.elements);
    builder.register_public_inputs(&merge_proof_target.new_user_asset_root.elements);
    let data = builder.build::<C>();

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

    let asset1 = ContributedAsset {
        receiver_address: user_address,
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(305)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 2053,
    };
    let asset2 = ContributedAsset {
        receiver_address: user_address,
        kind: TokenKind {
            contract_address: Address(*GoldilocksHashOut::from_u128(471)),
            variable_index: VariableIndex::from_hash_out(*GoldilocksHashOut::from_u128(8012)),
        },
        amount: 1111,
    };

    let mut user_asset_tree =
        UserAssetTree::<F, H>::new(LOG_MAX_N_TXS, LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);

    let mut deposit_tree =
        TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);

    deposit_tree.insert(asset1).unwrap();
    deposit_tree.insert(asset2).unwrap();

    // let deposit_tree: PoseidonSparseMerkleTree<_, _> = deposit_tree.into();

    let diff_tree_inclusion_proof2 = deposit_tree.prove_asset_root(&user_address).unwrap();
    let interior_deposit_root = deposit_tree.get_root().unwrap();

    let deposit_nonce = HashOut::ZERO;
    let deposit_tx_hash = H::two_to_one(interior_deposit_root, deposit_nonce);

    // let diff_tree = TxDiffTree::<F, H>::new(LOG_N_RECIPIENTS, LOG_N_CONTRACTS + LOG_N_VARIABLES);
    let diff_tree_inclusion_proof1 = get_merkle_proof::<F, H>(&[deposit_tx_hash], 0, LOG_N_TXS);

    let default_hash = HashOut::ZERO;
    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    let default_merkle_root = get_merkle_proof::<F, H>(&[], 0, LOG_N_TXS).root;
    let prev_block_header = BlockHeader {
        block_number: 1,
        prev_block_hash: default_hash,
        block_headers_digest: default_hash,
        transactions_digest: default_merkle_root,
        deposit_digest: diff_tree_inclusion_proof1.root,
        proposed_world_state_digest: default_hash,
        approved_world_state_digest: default_hash,
        latest_account_digest: default_hash,
    };
    let block_hash = get_block_hash(&prev_block_header);

    let deposit_merge_key = H::two_to_one(deposit_tx_hash, block_hash);

    let merge_inclusion_old_root = user_asset_tree.get_root().unwrap();
    // user asset tree に deposit を merge する.
    user_asset_tree
        .insert_assets(deposit_merge_key, vec![asset1, asset2])
        .unwrap();

    // let mut user_asset_tree: UserAssetTree<_, _> = user_asset_tree.into();
    let asset_root = user_asset_tree.get_asset_root(&deposit_merge_key).unwrap();
    {
        assert_eq!(asset_root, diff_tree_inclusion_proof2.value);
    }

    let merge_inclusion_new_root = user_asset_tree.get_root().unwrap();

    let merge_inclusion_proof = user_asset_tree
        .prove_asset_root(&deposit_merge_key)
        .unwrap();
    let merge_process_proof = MerkleProcessProof::<F, H, HashOut<F>> {
        index: deposit_merge_key,
        siblings: merge_inclusion_proof.siblings,
        old_value: HashOut::ZERO,
        new_value: asset_root,
        old_root: merge_inclusion_old_root,
        new_root: merge_inclusion_new_root,
    };

    let merge_proof = MergeProof::<F, H, _> {
        is_deposit: true,
        diff_tree_inclusion_proof: DiffTreeInclusionProof {
            block_header: prev_block_header,
            siblings1: diff_tree_inclusion_proof1.siblings,
            siblings2: diff_tree_inclusion_proof2.siblings,
            root1: diff_tree_inclusion_proof1.root,
            index1: diff_tree_inclusion_proof1.index,
            value1: diff_tree_inclusion_proof1.value,
            root2: diff_tree_inclusion_proof2.root,
            index2: diff_tree_inclusion_proof2.index,
            value2: diff_tree_inclusion_proof2.value,
        },
        merge_process_proof,
        latest_account_tree_inclusion_proof: default_inclusion_proof,
        nonce: deposit_nonce,
    };

    let mut pw = PartialWitness::new();

    merge_proof_target.set_witness(&mut pw, &[merge_proof], merge_inclusion_old_root);

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

    merge_proof_target.set_witness::<F, H>(&mut pw, &[], default_hash);

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
