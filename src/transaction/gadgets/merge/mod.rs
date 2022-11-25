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
}

#[derive(Clone, Debug)]
pub struct MergeProofTarget<
    const N_LOG_MAX_USERS: usize,
    const N_LOG_MAX_TXS: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
> {
    // pub is_deposit: BoolTarget,
    pub diff_tree_inclusion_proof: (
        BlockHeaderTarget,
        MerkleProofTarget<N_LOG_TXS>,
        SparseMerkleInclusionProofTarget<N_LOG_RECIPIENTS>,
    ),
    pub merge_process_proof: SparseMerkleProcessProofTarget<N_LOG_MAX_TXS>,
    pub address_list_inclusion_proof: SparseMerkleInclusionProofTarget<N_LOG_MAX_USERS>,
}

#[derive(Clone, Debug)]
pub struct MergeTransitionTarget<
    const N_LOG_MAX_USERS: usize,
    const N_LOG_MAX_TXS: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_MERGES: usize,
> {
    pub proofs:
        [MergeProofTarget<N_LOG_MAX_USERS, N_LOG_MAX_TXS, N_LOG_TXS, N_LOG_RECIPIENTS>; N_MERGES],
    pub old_user_asset_root: HashOutTarget,
    pub new_user_asset_root: HashOutTarget,
}

impl<
        const N_LOG_MAX_USERS: usize,
        const N_LOG_MAX_TXS: usize,
        const N_LOG_TXS: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_MERGES: usize,
    > MergeTransitionTarget<N_LOG_MAX_USERS, N_LOG_MAX_TXS, N_LOG_TXS, N_LOG_RECIPIENTS, N_MERGES>
{
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let mut proofs = vec![];
        for _ in 0..N_MERGES {
            let target = MergeProofTarget {
                // is_deposit: builder.add_virtual_bool_target_safe(),
                diff_tree_inclusion_proof: (
                    BlockHeaderTarget::add_virtual_to::<F, H, D>(builder),
                    MerkleProofTarget::add_virtual_to::<F, H, D>(builder),
                    SparseMerkleInclusionProofTarget::add_virtual_to::<F, H, D>(builder),
                ),
                merge_process_proof: SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(
                    builder,
                ),
                address_list_inclusion_proof: SparseMerkleInclusionProofTarget::add_virtual_to::<
                    F,
                    H,
                    D,
                >(builder),
            };

            proofs.push(target);
        }

        let old_user_asset_root = builder.add_virtual_hash();
        let new_user_asset_root = verify_user_asset_merge_proof::<
            F,
            H,
            D,
            N_LOG_MAX_USERS,
            N_LOG_MAX_TXS,
            N_LOG_TXS,
            N_LOG_RECIPIENTS,
        >(builder, &proofs, old_user_asset_root);

        Self {
            proofs: proofs.try_into().unwrap(),
            old_user_asset_root,
            new_user_asset_root,
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

            let block_header = witness.diff_tree_inclusion_proof.0.clone();
            let root = if witness.is_deposit {
                block_header.deposit_digest
            } else {
                block_header.transactions_digest
            };
            assert_eq!(root, *witness.diff_tree_inclusion_proof.1.root);
            let block_hash = get_block_hash(&witness.diff_tree_inclusion_proof.0);
            let deposit_tx_hash =
                PoseidonHash::two_to_one(*witness.diff_tree_inclusion_proof.2.root, block_hash)
                    .into();
            let purge_tx_hash = witness.diff_tree_inclusion_proof.2.root;
            let tx_hash = if witness.is_deposit {
                deposit_tx_hash
            } else {
                assert_eq!(
                    witness.latest_account_tree_inclusion_proof.value.to_u32(),
                    witness.diff_tree_inclusion_proof.0.block_number,
                );

                purge_tx_hash
            };

            assert_eq!(witness.merge_process_proof.new_key, tx_hash);
            assert_eq!(witness.diff_tree_inclusion_proof.1.value, tx_hash);
            assert_eq!(witness.merge_process_proof.old_value, Default::default());
            assert_eq!(
                witness.merge_process_proof.new_value,
                witness.diff_tree_inclusion_proof.2.value,
            );
            assert_eq!(
                witness.diff_tree_inclusion_proof.0.latest_account_digest,
                *witness.latest_account_tree_inclusion_proof.root,
            ); // XXX
            assert_eq!(witness.merge_process_proof.old_root, new_user_asset_root);

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

            target.address_list_inclusion_proof.set_witness(
                pw,
                &witness.latest_account_tree_inclusion_proof,
                !witness.is_deposit,
            );

            new_user_asset_root = witness.merge_process_proof.new_root
        }

        let default_header = BlockHeader::default();
        let default_inclusion_proof = SmtInclusionProof::with_root(Default::default());
        let default_process_proof = SmtProcessProof::with_root(new_user_asset_root);
        for target in self.proofs.iter().skip(proofs.len()) {
            // pw.set_bool_target(target.is_deposit, true);
            target
                .diff_tree_inclusion_proof
                .0
                .set_witness(pw, &default_header);
            target
                .diff_tree_inclusion_proof
                .1
                .set_witness(pw, 0, WrappedHashOut::ZERO, &[]);
            target
                .diff_tree_inclusion_proof
                .2
                .set_witness(pw, &default_inclusion_proof, false);

            target
                .merge_process_proof
                .set_witness(pw, &default_process_proof);

            target
                .address_list_inclusion_proof
                .set_witness(pw, &default_inclusion_proof, false);
        }

        new_user_asset_root
    }
}

pub fn verify_user_asset_merge_proof<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
    const N_LOG_MAX_USERS: usize,
    const N_LOG_MAX_TXS: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    proofs: &[MergeProofTarget<N_LOG_MAX_USERS, N_LOG_MAX_TXS, N_LOG_TXS, N_LOG_RECIPIENTS>],
    old_user_asset_root: HashOutTarget,
) -> HashOutTarget {
    let zero = builder.zero();
    let default_hash = HashOutTarget {
        elements: [zero; 4],
    };

    let mut new_user_asset_root = old_user_asset_root;
    for MergeProofTarget {
        // is_deposit: actual_is_deposit,
        merge_process_proof,
        diff_tree_inclusion_proof,
        address_list_inclusion_proof,
    } in proofs
    {
        let is_not_deposit = builder.not(address_list_inclusion_proof.enabled);

        // let is_not_no_op = diff_tree_inclusion_proof.1.enabled;
        let ProcessMerkleProofRoleTarget { is_not_no_op, .. } =
            get_process_merkle_proof_role::<F, D>(builder, merge_process_proof.fnc);

        let block_header_t = diff_tree_inclusion_proof.0.clone();
        let root = conditionally_select(
            builder,
            block_header_t.transactions_digest,
            block_header_t.deposit_digest,
            is_not_deposit,
        ); // XXX: row 2064, column 79 は最初のループのここ
        enforce_equal_if_enabled(
            builder,
            root,
            diff_tree_inclusion_proof.1.root,
            is_not_no_op,
        );

        let receiving_block_number = diff_tree_inclusion_proof.0.block_number;
        let confirmed_block_number = address_list_inclusion_proof.value; // 最後に成功した block number

        let check_block_number = builder.and(is_not_no_op, is_not_deposit);
        enforce_equal_if_enabled(
            builder,
            confirmed_block_number,
            HashOutTarget::from_partial(&[receiving_block_number], zero),
            check_block_number,
        );

        // deposit と purge の場合で tx_hash の計算方法が異なる.
        let block_hash = get_block_hash_target::<F, H, D>(builder, &diff_tree_inclusion_proof.0);
        let deposit_tx_hash =
            poseidon_two_to_one::<F, H, D>(builder, diff_tree_inclusion_proof.2.root, block_hash);
        let purge_tx_hash = diff_tree_inclusion_proof.2.root;
        let tx_hash = conditionally_select(builder, purge_tx_hash, deposit_tx_hash, is_not_deposit);

        enforce_equal_if_enabled(
            builder,
            diff_tree_inclusion_proof.1.value,
            tx_hash,
            check_block_number,
        );
        enforce_equal_if_enabled(
            builder,
            merge_process_proof.new_key,
            tx_hash,
            check_block_number,
        );
        enforce_equal_if_enabled(
            builder,
            merge_process_proof.old_value,
            default_hash,
            is_not_no_op,
        );
        enforce_equal_if_enabled(
            builder,
            merge_process_proof.new_value,
            diff_tree_inclusion_proof.2.value,
            is_not_no_op,
        ); // XXX: row 2079, column 3 は最初のループのここ
        enforce_equal_if_enabled(
            builder,
            diff_tree_inclusion_proof.0.latest_account_digest,
            address_list_inclusion_proof.root,
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
