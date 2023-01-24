use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    config::RollupConstants,
    merkle_tree::tree::{get_merkle_root, MerkleProcessProof},
    sparse_merkle_tree::{
        gadgets::process::process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
        proof::SparseMerkleProcessProof,
    },
    transaction::{
        asset::{ContributedAsset, TokenKind},
        circuits::{
            MergeAndPurgeTransition, MergeAndPurgeTransitionPublicInputs,
            MergeAndPurgeTransitionPublicInputsTarget,
        },
        gadgets::{
            merge::DiffTreeInclusionProof,
            purge::{PurgeInputProcessProof, PurgeOutputProcessProof},
        },
        tree::tx_diff::TxDiffTree,
    },
    utils::{
        gadgets::logic::{conditionally_select, enforce_equal_if_enabled},
        hash::WrappedHashOut,
    },
    zkdsa::{
        account::Address,
        circuits::{SimpleSignaturePublicInputs, SimpleSignaturePublicInputsTarget},
        gadgets::signature::SimpleSignature,
    },
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedMessage<F: RichField> {
    message: HashOut<F>,
    public_key: HashOut<F>,
    signature: HashOut<F>,
}

#[derive(Clone)]
pub struct WorldStateRevertTransitionTarget {
    pub world_state_revert_proof: SparseMerkleProcessProofTarget,

    pub user_transaction: MergeAndPurgeTransitionPublicInputsTarget,

    pub received_signature: (SimpleSignaturePublicInputsTarget, BoolTarget),

    pub latest_account_process_proof: SparseMerkleProcessProofTarget,

    pub enabled: BoolTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalBlockProduction<F: RichField> {
    pub current_block_number: u32,
    pub world_state_revert_proofs: Vec<SmtProcessProof<F>>,
    pub user_transactions: Vec<MergeAndPurgeTransitionPublicInputs<F>>,
    pub received_signatures: Vec<Option<SimpleSignaturePublicInputs<F>>>,
    pub latest_account_tree_process_proofs: Vec<SmtProcessProof<F>>,
    pub old_world_state_root: WrappedHashOut<F>,
    pub old_latest_account_root: WrappedHashOut<F>,
}

impl<F: RichField> ApprovalBlockProduction<F> {
    /// Returns `(new_world_state_root, new_latest_account_root)`
    pub fn calculate(&self) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
        let mut prev_world_state_root = self.old_world_state_root;
        let mut prev_latest_account_root = self.old_latest_account_root;
        for (world_state_revert_proof, latest_account_process_proof) in self
            .world_state_revert_proofs
            .iter()
            .zip(self.latest_account_tree_process_proofs.iter())
        {
            assert_eq!(world_state_revert_proof.old_root, prev_world_state_root);
            assert_eq!(
                latest_account_process_proof.old_root,
                prev_latest_account_root
            );

            prev_world_state_root = world_state_revert_proof.new_root;
            prev_latest_account_root = latest_account_process_proof.new_root;
        }
        let new_world_state_root = prev_world_state_root;
        let new_latest_account_root = prev_latest_account_root;

        for (((w, u), r), a) in self
            .world_state_revert_proofs
            .iter()
            .zip(self.user_transactions.iter())
            .zip(self.received_signatures.iter())
            .zip(self.latest_account_tree_process_proofs.iter())
        {
            // proposed block では, user asset root は `u.new_user_asset_root` と同じであった.
            assert_eq!(w.old_value, u.new_user_asset_root);

            // merge までは signature がなくても実行されるが, purge は signature がない時には実行されない.
            let expected_new_last_block_number = if let Some(signature) = r {
                // signature が特定のメッセージに署名している時のみ有効である.
                assert_eq!(signature.message, *self.old_world_state_root);
                // signature が提出された時, user asset root は変わらない.
                assert_eq!(w.new_value, u.new_user_asset_root);

                WrappedHashOut::from_u32(self.current_block_number)
            } else {
                // signature がない時は, user asset root が merge 直後の状態 `u.middle_user_asset_root` に更新される
                assert_eq!(w.new_value, u.middle_user_asset_root);

                a.old_value
            };

            assert_eq!(a.new_value, expected_new_last_block_number);
        }

        (new_world_state_root, new_latest_account_root)
    }
}

#[derive(Clone)]
pub struct ApprovalBlockProductionTarget {
    pub current_block_number: Target,

    pub world_state_revert_transitions: Vec<WorldStateRevertTransitionTarget>,

    pub old_world_state_root: HashOutTarget,

    pub new_world_state_root: HashOutTarget,

    pub old_latest_account_root: HashOutTarget,

    pub new_latest_account_root: HashOutTarget,

    pub log_max_n_users: usize, // constant
}

impl ApprovalBlockProductionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_users: usize,
        n_txs: usize,
    ) -> Self {
        let current_block_number = builder.add_virtual_target();

        let mut world_state_revert_transitions = vec![];
        for _ in 0..n_txs {
            let world_state_revert_proof =
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_users);
            let user_transaction =
                MergeAndPurgeTransitionPublicInputsTarget::add_virtual_to(builder);
            let signature = SimpleSignaturePublicInputsTarget::add_virtual_to(builder);
            let validity = builder.add_virtual_bool_target_safe();
            let latest_account_process_proof =
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder, log_max_n_users);
            let enabled = builder.add_virtual_bool_target_safe();
            world_state_revert_transitions.push(WorldStateRevertTransitionTarget {
                world_state_revert_proof,
                user_transaction,
                received_signature: (signature, validity),
                latest_account_process_proof,
                enabled,
            });
        }
        let old_world_state_root = builder.add_virtual_hash();

        let old_latest_account_root = builder.add_virtual_hash();

        let (new_world_state_root, new_latest_account_root) = verify_valid_approval_block::<F, H, D>(
            builder,
            current_block_number,
            &world_state_revert_transitions,
            old_world_state_root,
            old_latest_account_root,
        );

        Self {
            current_block_number,
            world_state_revert_transitions,
            old_world_state_root,
            new_world_state_root,
            old_latest_account_root,
            new_latest_account_root,
            log_max_n_users,
        }
    }

    /// Returns `(new_world_state_root, new_latest_account_root)`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &ApprovalBlockProduction<F>,
    ) -> (WrappedHashOut<F>, WrappedHashOut<F>) {
        // assert!(!user_transactions.is_empty());

        let (new_world_state_root, new_latest_account_root) = witness.calculate();

        pw.set_hash_target(self.old_world_state_root, *witness.old_world_state_root);
        pw.set_hash_target(
            self.old_latest_account_root,
            *witness.old_latest_account_root,
        );

        pw.set_target(
            self.current_block_number,
            F::from_canonical_u32(witness.current_block_number),
        );
        for (t, w) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.world_state_revert_proofs.iter())
        {
            t.world_state_revert_proof.set_witness(pw, w);
        }

        let default_proof = SmtProcessProof::with_root(new_world_state_root);
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.world_state_revert_proofs.len())
        {
            t.world_state_revert_proof.set_witness(pw, &default_proof);
        }

        for (t, u) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.user_transactions.iter())
        {
            t.user_transaction.set_witness(pw, u);
        }
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.user_transactions.len())
        {
            t.user_transaction.set_witness(pw, &Default::default());
        }

        for (t, r) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.received_signatures.iter())
        {
            let r: Option<&_> = r.into();
            t.received_signature
                .0
                .set_witness(pw, r.unwrap_or(&Default::default()));
            pw.set_bool_target(t.received_signature.1, r.is_some());
        }
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.received_signatures.len())
        {
            t.received_signature.0.set_witness(pw, &Default::default());
            pw.set_bool_target(t.received_signature.1, false);
        }

        for t in self
            .world_state_revert_transitions
            .iter()
            .take(witness.user_transactions.len())
        {
            pw.set_bool_target(t.enabled, true);
        }

        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.user_transactions.len())
        {
            pw.set_bool_target(t.enabled, false);
        }

        for (t, a) in self
            .world_state_revert_transitions
            .iter()
            .zip(witness.latest_account_tree_process_proofs.iter())
        {
            t.latest_account_process_proof.set_witness(pw, a);
        }

        let default_proof = SmtProcessProof::with_root(new_latest_account_root);
        for t in self
            .world_state_revert_transitions
            .iter()
            .skip(witness.latest_account_tree_process_proofs.len())
        {
            t.latest_account_process_proof
                .set_witness(pw, &default_proof);
        }

        (new_world_state_root, new_latest_account_root)
    }
}

/// Returns `(old_world_state_root, new_world_state_root, old_account_tree_root, new_account_tree_root)`
#[allow(clippy::too_many_arguments)]
pub fn verify_valid_approval_block<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    current_block_number: Target,
    world_state_revert_transitions: &[WorldStateRevertTransitionTarget],
    old_world_state_root: HashOutTarget,
    old_latest_account_root: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let zero = builder.zero();

    // world state process proof と latest account process proof は正しい遷移になるように並んでいる.
    let mut prev_world_state_root = old_world_state_root;
    let mut prev_latest_account_root = old_latest_account_root;
    for WorldStateRevertTransitionTarget {
        world_state_revert_proof,
        latest_account_process_proof,
        ..
    } in world_state_revert_transitions
    {
        builder.connect_hashes(world_state_revert_proof.old_root, prev_world_state_root);
        builder.connect_hashes(
            latest_account_process_proof.old_root,
            prev_latest_account_root,
        );

        prev_world_state_root = world_state_revert_proof.new_root;
        prev_latest_account_root = latest_account_process_proof.new_root;
    }
    let new_world_state_root = prev_world_state_root;
    let new_latest_account_root = prev_latest_account_root;

    for WorldStateRevertTransitionTarget {
        world_state_revert_proof: w,
        user_transaction: u,
        received_signature: r,
        latest_account_process_proof: a,
        enabled,
        ..
    } in world_state_revert_transitions
    {
        let (signature, enabled_signature) = r;

        // 特定のメッセージに署名したことを確かめる.
        enforce_equal_if_enabled(
            builder,
            signature.message,
            old_world_state_root, // = proposal_world_state_root
            *enabled_signature,
        );

        enforce_equal_if_enabled(builder, w.old_value, u.new_user_asset_root, *enabled);

        let expected_new_root = conditionally_select(
            builder,
            u.new_user_asset_root,
            u.middle_user_asset_root,
            *enabled_signature,
        );
        enforce_equal_if_enabled(builder, w.new_value, expected_new_root, *enabled);

        let old_last_block_number = a.old_value.elements[0];
        builder.connect(a.old_value.elements[1], zero);
        builder.connect(a.old_value.elements[2], zero);
        builder.connect(a.old_value.elements[3], zero);
        let new_last_block_number = a.new_value.elements[0];
        builder.connect(a.new_value.elements[1], zero);
        builder.connect(a.new_value.elements[2], zero);
        builder.connect(a.new_value.elements[3], zero);

        let expected_new_last_block_number = builder._if(
            *enabled_signature,
            current_block_number,
            old_last_block_number,
        );
        builder.connect(expected_new_last_block_number, new_last_block_number);
    }

    (new_world_state_root, new_latest_account_root)
}

#[allow(clippy::complexity)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleBlock<F: RichField, H: AlgebraicHasher<F>> {
    pub transactions: Vec<(MergeAndPurgeTransition<F, H>, Option<SimpleSignature<F>>)>,
    pub old_world_state_root: HashOut<F>,
    pub world_state_process_proofs:
        Vec<SparseMerkleProcessProof<WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>>>,
    pub approval_block: ApprovalBlockProduction<F>,
}

/// Returns `(stored_transactions, approval_block, new_world_root)`
pub fn make_sample_circuit_inputs<C: GenericConfig<D, F = GoldilocksField>, const D: usize>(
    rollup_constants: RollupConstants,
) -> Vec<SampleBlock<GoldilocksField, C::InnerHasher>> {
    use plonky2::{field::types::Field, hash::poseidon::PoseidonHash, plonk::config::Hasher};

    use crate::{
        merkle_tree::tree::get_merkle_proof,
        sparse_merkle_tree::{
            goldilocks_poseidon::{NodeDataMemory, PoseidonSparseMerkleTree, RootDataTmp},
            proof::SparseMerkleInclusionProof,
        },
        transaction::{
            block_header::{get_block_hash, BlockHeader},
            gadgets::merge::MergeProof,
            tree::user_asset::UserAssetTree,
        },
        utils::hash::GoldilocksHashOut,
        zkdsa::account::private_key_to_account,
    };

    let aggregator_nodes_db = NodeDataMemory::default();
    let mut world_state_tree =
        PoseidonSparseMerkleTree::new(aggregator_nodes_db, RootDataTmp::default());

    let sender1_private_key = HashOut {
        elements: [
            C::F::from_canonical_u64(17426287337377512978),
            C::F::from_canonical_u64(8703645504073070742),
            C::F::from_canonical_u64(11984317793392655464),
            C::F::from_canonical_u64(9979414176933652180),
        ],
    };
    let sender1_account = private_key_to_account(sender1_private_key);
    let sender1_address = sender1_account.address;

    let mut sender1_user_asset_tree = UserAssetTree::<_, C::InnerHasher>::new(
        rollup_constants.log_max_n_txs,
        rollup_constants.log_max_n_contracts + rollup_constants.log_max_n_variables,
    );

    let mut sender1_tx_diff_tree = TxDiffTree::<_, C::InnerHasher>::new(
        rollup_constants.log_n_recipients,
        rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
    );

    let merge_key1 = GoldilocksHashOut::from_u128(1);
    let merge_key2 = GoldilocksHashOut::from_u128(12);
    let asset1 = ContributedAsset {
        receiver_address: sender1_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(305).0),
            variable_index: 8u8.into(),
        },
        amount: 2053,
    };
    let asset2 = ContributedAsset {
        receiver_address: sender1_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(471).0),
            variable_index: 8u8.into(),
        },
        amount: 1111,
    };

    let asset3 = ContributedAsset {
        receiver_address: sender1_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(305).0),
            variable_index: 8u8.into(),
        },
        amount: 2,
    };
    let asset4 = ContributedAsset {
        receiver_address: sender1_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(471).0),
            variable_index: 8u8.into(),
        },
        amount: 1111,
    };

    sender1_user_asset_tree
        .insert_assets(*merge_key1, vec![asset1])
        .unwrap();

    sender1_user_asset_tree
        .insert_assets(*merge_key2, vec![asset2])
        .unwrap();

    world_state_tree
        .set(
            sender1_account.address.0.into(),
            sender1_user_asset_tree.get_root().unwrap().into(),
        )
        .unwrap();
    let old_sender1_asset_root = sender1_user_asset_tree.get_root().unwrap();

    let proof2 = sender1_user_asset_tree
        .prove_leaf_node(&merge_key2, &asset2.receiver_address, &asset2.kind)
        .unwrap();
    let proof2 = PurgeInputProcessProof {
        siblings: proof2.siblings,
        index: proof2.index,
        old_leaf_data: asset2,
    };
    sender1_user_asset_tree
        .remove(*merge_key2, asset2.receiver_address, asset2.kind)
        .unwrap();
    let proof1 = sender1_user_asset_tree
        .prove_leaf_node(&merge_key1, &asset1.receiver_address, &asset1.kind)
        .unwrap();
    let proof1 = PurgeInputProcessProof {
        siblings: proof1.siblings,
        index: proof1.index,
        old_leaf_data: asset1,
    };
    sender1_user_asset_tree
        .remove(*merge_key1, asset1.receiver_address, asset1.kind)
        .unwrap();

    let new_sender1_asset_root = sender1_user_asset_tree.get_root().unwrap();
    dbg!(&new_sender1_asset_root);

    sender1_tx_diff_tree.insert(asset3).unwrap();
    let proof3 = sender1_tx_diff_tree
        .prove_leaf_node(&sender1_address, &asset3.kind)
        .unwrap();
    let proof3 = PurgeOutputProcessProof {
        siblings: proof3.siblings,
        index: proof3.index,
        new_leaf_data: asset3,
    };
    sender1_tx_diff_tree.insert(asset4).unwrap();
    let proof4 = sender1_tx_diff_tree
        .prove_leaf_node(&sender1_address, &asset4.kind)
        .unwrap();
    let proof4 = PurgeOutputProcessProof {
        siblings: proof4.siblings,
        index: proof4.index,
        new_leaf_data: asset4,
    };

    let sender1_input_witness = vec![proof2, proof1];
    let sender1_output_witness = vec![proof3, proof4];

    let sender2_private_key = HashOut {
        elements: [
            C::F::from_canonical_u64(15657143458229430356),
            C::F::from_canonical_u64(6012455030006979790),
            C::F::from_canonical_u64(4280058849535143691),
            C::F::from_canonical_u64(5153662694263190591),
        ],
    };
    let sender2_account = private_key_to_account(sender2_private_key);
    let sender2_address = sender2_account.address;

    let mut sender2_user_asset_tree = UserAssetTree::<_, C::InnerHasher>::new(
        rollup_constants.log_max_n_txs,
        rollup_constants.log_max_n_contracts + rollup_constants.log_max_n_variables,
    );

    let mut sender2_tx_diff_tree = TxDiffTree::<_, C::InnerHasher>::new(
        rollup_constants.log_n_recipients,
        rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
    );

    let mut block0_deposit_tree = TxDiffTree::<_, C::InnerHasher>::new(
        rollup_constants.log_n_recipients,
        rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
    );

    let asset1 = ContributedAsset {
        receiver_address: sender2_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(305).0),
            variable_index: 8u8.into(),
        },
        amount: 2053,
    };
    let asset2 = ContributedAsset {
        receiver_address: sender2_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(471).0),
            variable_index: 8u8.into(),
        },
        amount: 1111,
    };

    let asset3 = ContributedAsset {
        receiver_address: sender2_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(305).0),
            variable_index: 8u8.into(),
        },
        amount: 2,
    };
    let asset4 = ContributedAsset {
        receiver_address: sender2_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(471).0),
            variable_index: 8u8.into(),
        },
        amount: 1111,
    };

    block0_deposit_tree.insert(asset1).unwrap();
    block0_deposit_tree.insert(asset2).unwrap();

    // let block0_deposit_tree: PoseidonSparseMerkleTree<_, _> = block0_deposit_tree.into();

    let merge_inclusion_root2 = block0_deposit_tree
        .get_asset_root(&sender2_address)
        .unwrap();

    // `merge_inclusion_proof2` の root を `diff_root`, `hash(diff_root, nonce)` の値を `tx_hash` とよぶ.
    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root = merge_inclusion_root2;
    let deposit_tx_hash = PoseidonHash::two_to_one(deposit_diff_root, deposit_nonce);

    let diff_tree_inclusion_proof1 =
        get_merkle_proof::<_, C::InnerHasher>(&[deposit_tx_hash], 0, rollup_constants.log_n_txs);

    let diff_tree_inclusion_proof2 = block0_deposit_tree
        .prove_asset_root(&sender2_address)
        .unwrap();

    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    // let default_merkle_root = get_merkle_proof(&[], 0, LOG_N_TXS).root;
    let mut prev_block_header = BlockHeader::new(rollup_constants.log_n_txs);
    prev_block_header.block_number = 1;
    prev_block_header.deposit_digest = diff_tree_inclusion_proof1.root;

    let block_hash = get_block_hash(&prev_block_header);

    world_state_tree
        .set(
            sender2_address.0.into(),
            sender2_user_asset_tree.get_root().unwrap().into(),
        )
        .unwrap();

    // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    let deposit_merge_key = PoseidonHash::two_to_one(deposit_tx_hash, block_hash);

    // user_asset_tree に deposit を merge する.
    let old_sender2_asset_root = sender2_user_asset_tree.get_root().unwrap();
    let old_sender2_asset_value = sender2_user_asset_tree
        .get_asset_root(&deposit_merge_key)
        .unwrap();
    sender2_user_asset_tree
        .insert_assets(deposit_merge_key, vec![asset1, asset2])
        .unwrap();
    let merge_inclusion_proof = sender2_user_asset_tree
        .prove_asset_root(&deposit_merge_key)
        .unwrap();
    let merge_process_proof = MerkleProcessProof {
        index: merge_inclusion_proof.index,
        siblings: merge_inclusion_proof.siblings,
        old_value: old_sender2_asset_value,
        new_value: merge_inclusion_proof.value,
        old_root: old_sender2_asset_root,
        new_root: merge_inclusion_proof.root,
    };

    let diff_tree_inclusion_proof = DiffTreeInclusionProof {
        block_header: prev_block_header.clone(),
        siblings1: diff_tree_inclusion_proof1.siblings,
        root1: diff_tree_inclusion_proof1.root,
        index1: diff_tree_inclusion_proof1.index,
        value1: diff_tree_inclusion_proof1.value,
        siblings2: diff_tree_inclusion_proof2.siblings,
        root2: diff_tree_inclusion_proof2.root,
        index2: diff_tree_inclusion_proof2.index,
        value2: diff_tree_inclusion_proof2.value,
    };

    let merge_proof = MergeProof {
        is_deposit: true,
        diff_tree_inclusion_proof,
        merge_process_proof,
        latest_account_tree_inclusion_proof: default_inclusion_proof,
        nonce: deposit_nonce,
    };

    let middle_sender2_asset_root = sender2_user_asset_tree.get_root().unwrap();
    dbg!(middle_sender2_asset_root);

    let proof2 = sender2_user_asset_tree
        .prove_leaf_node(&deposit_merge_key, &asset2.receiver_address, &asset2.kind)
        .unwrap();
    let proof2 = PurgeInputProcessProof {
        siblings: proof2.siblings,
        index: proof2.index,
        old_leaf_data: asset2,
    };
    sender2_user_asset_tree
        .remove(deposit_merge_key, sender2_address, asset2.kind)
        .unwrap();
    let proof1 = sender2_user_asset_tree
        .prove_leaf_node(&deposit_merge_key, &asset1.receiver_address, &asset1.kind)
        .unwrap();
    let proof1 = PurgeInputProcessProof {
        siblings: proof1.siblings,
        index: proof1.index,
        old_leaf_data: asset1,
    };
    sender2_user_asset_tree
        .remove(deposit_merge_key, sender2_address, asset1.kind)
        .unwrap();
    let new_sender2_asset_root = sender2_user_asset_tree.get_root().unwrap();
    dbg!(new_sender2_asset_root);

    sender2_tx_diff_tree.insert(asset3).unwrap();
    let proof3 = sender2_tx_diff_tree
        .prove_leaf_node(&asset3.receiver_address, &asset3.kind)
        .unwrap();
    let proof3 = PurgeOutputProcessProof {
        siblings: proof3.siblings,
        index: proof3.index,
        new_leaf_data: asset3,
    };
    sender2_tx_diff_tree.insert(asset4).unwrap();
    let proof4 = sender2_tx_diff_tree
        .prove_leaf_node(&asset4.receiver_address, &asset4.kind)
        .unwrap();
    let proof4 = PurgeOutputProcessProof {
        siblings: proof4.siblings,
        index: proof4.index,
        new_leaf_data: asset4,
    };

    let sender2_input_witness = vec![proof2, proof1];
    let sender2_output_witness = vec![proof3, proof4];

    let sender1_nonce = WrappedHashOut::from(HashOut {
        elements: [
            C::F::from_canonical_u64(7823975322825286183),
            C::F::from_canonical_u64(9539665429968124165),
            C::F::from_canonical_u64(6825628074508059665),
            C::F::from_canonical_u64(17852854585777218254),
        ],
    });

    let sender1_merge_and_purge_transition = MergeAndPurgeTransition {
        sender_address: sender1_account.address,
        merge_witnesses: vec![],
        purge_input_witnesses: sender1_input_witness,
        purge_output_witnesses: sender1_output_witness,
        nonce: *sender1_nonce,
        old_user_asset_root: old_sender1_asset_root,
    };
    let actual_old_root = get_merkle_root::<_, PoseidonHash, _>(
        &sender1_merge_and_purge_transition.purge_input_witnesses[0].index,
        PoseidonHash::hash_or_noop(&ContributedAsset::default().encode()),
        &sender1_merge_and_purge_transition.purge_input_witnesses[0].siblings,
    );
    dbg!(
        &sender1_merge_and_purge_transition.old_user_asset_root,
        actual_old_root
    );
    let sender1_tx_pis = {
        let (middle_user_asset_root, new_user_asset_root, diff_root, tx_hash) =
            sender1_merge_and_purge_transition.calculate(
                rollup_constants.log_n_recipients,
                rollup_constants.log_n_contracts + rollup_constants.log_max_n_variables,
            );

        MergeAndPurgeTransitionPublicInputs {
            sender_address: sender1_merge_and_purge_transition.sender_address,
            old_user_asset_root: sender1_merge_and_purge_transition
                .old_user_asset_root
                .into(),
            middle_user_asset_root: middle_user_asset_root.into(),
            new_user_asset_root: new_user_asset_root.into(),
            diff_root: diff_root.into(),
            tx_hash: tx_hash.into(),
        }
    };

    let sender2_nonce = WrappedHashOut::from(HashOut {
        elements: [
            C::F::from_canonical_u64(6657881311364026367),
            C::F::from_canonical_u64(11761473381903976612),
            C::F::from_canonical_u64(10768494808833234712),
            C::F::from_canonical_u64(3223267375194257474),
        ],
    });

    let sender2_merge_and_purge_transition = MergeAndPurgeTransition {
        sender_address: sender2_account.address,
        merge_witnesses: vec![merge_proof],
        purge_input_witnesses: sender2_input_witness,
        purge_output_witnesses: sender2_output_witness,
        nonce: *sender2_nonce,
        old_user_asset_root: old_sender2_asset_root,
    };
    let sender2_tx_pis = {
        let (middle_user_asset_root, new_user_asset_root, diff_root, tx_hash) =
            sender2_merge_and_purge_transition.calculate(
                rollup_constants.log_n_recipients,
                rollup_constants.log_n_contracts + rollup_constants.log_max_n_variables,
            );

        MergeAndPurgeTransitionPublicInputs {
            sender_address: sender2_merge_and_purge_transition.sender_address,
            old_user_asset_root: sender2_merge_and_purge_transition
                .old_user_asset_root
                .into(),
            middle_user_asset_root: middle_user_asset_root.into(),
            new_user_asset_root: new_user_asset_root.into(),
            diff_root: diff_root.into(),
            tx_hash: tx_hash.into(),
        }
    };

    let old_world_state_root = *world_state_tree.get_root().unwrap();

    let mut world_state_process_proofs = vec![];
    let mut user_transactions = vec![];

    let sender1_world_state_process_proof = world_state_tree
        .set(
            sender1_address.0.into(),
            sender1_user_asset_tree.get_root().unwrap().into(),
        )
        .unwrap();

    let sender2_world_state_process_proof = world_state_tree
        .set(
            sender2_address.0.into(),
            sender2_user_asset_tree.get_root().unwrap().into(),
        )
        .unwrap();

    let proposed_world_state_root = *world_state_tree.get_root().unwrap();

    world_state_process_proofs.push(sender1_world_state_process_proof);
    user_transactions.push(sender1_tx_pis.clone());
    world_state_process_proofs.push(sender2_world_state_process_proof);
    user_transactions.push(sender2_tx_pis.clone());

    let block_number = prev_block_header.block_number + 1;

    let stored_transactions: Vec<(_, _)> = vec![(false, sender1_tx_pis), (true, sender2_tx_pis)];

    let mut latest_account_tree =
        PoseidonSparseMerkleTree::new(NodeDataMemory::default(), RootDataTmp::default());

    // NOTICE: merge proof の中に deposit が混ざっていると, revert proof がうまく出せない場合がある.
    // deposit してそれを消費して old: 0 -> middle: non-zero -> new: 0 となった場合は,
    // u.enabled かつ w.fnc == NoOp だが revert ではない.
    let mut world_state_revert_proofs = vec![];
    let mut latest_account_tree_process_proofs = vec![];
    for (opt_received_signature, user_tx_pis) in stored_transactions {
        let user_address = user_tx_pis.sender_address;
        let (last_block_number, confirmed_user_asset_root) = if !opt_received_signature {
            let old_block_number = latest_account_tree.get(&user_address.0.into()).unwrap();
            (
                old_block_number.to_u32(),
                user_tx_pis.middle_user_asset_root,
            )
        } else {
            (block_number, user_tx_pis.new_user_asset_root)
        };
        latest_account_tree_process_proofs.push(
            latest_account_tree
                .set(
                    user_address.0.into(),
                    GoldilocksHashOut::from_u32(last_block_number),
                )
                .unwrap(),
        );

        let proof = world_state_tree
            .set(user_address.0.into(), confirmed_user_asset_root)
            .unwrap();
        world_state_revert_proofs.push(proof);
    }

    // let approved_world_state_root = *world_state_tree.get_root().unwrap();

    let sender2_received_signatures = SimpleSignature {
        private_key: sender2_account.private_key,
        message: proposed_world_state_root,
    };
    let received_signatures = vec![None, Some(sender2_received_signatures.calculate())];
    let old_latest_account_root = latest_account_tree_process_proofs.first().unwrap().old_root;
    let approval_block = ApprovalBlockProduction {
        current_block_number: block_number,
        world_state_revert_proofs: world_state_revert_proofs.clone(),
        user_transactions,
        received_signatures,
        latest_account_tree_process_proofs: latest_account_tree_process_proofs.clone(),
        old_world_state_root: proposed_world_state_root.into(),
        old_latest_account_root,
    };

    vec![SampleBlock {
        transactions: vec![
            (sender1_merge_and_purge_transition, None),
            (
                sender2_merge_and_purge_transition,
                Some(sender2_received_signatures),
            ),
        ],
        old_world_state_root,
        world_state_process_proofs,
        approval_block,
    }]
}

#[cfg(test)]
mod tests {
    use crate::{
        config::RollupConstants,
        rollup::gadgets::approval_block::{
            make_sample_circuit_inputs, ApprovalBlockProductionTarget,
        },
    };

    #[test]
    fn test_approval_block() {
        use std::time::Instant;

        use plonky2::{
            iop::witness::PartialWitness,
            plonk::{
                circuit_builder::CircuitBuilder,
                circuit_data::CircuitConfig,
                config::{GenericConfig, PoseidonGoldilocksConfig},
            },
        };

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type H = <C as GenericConfig<D>>::InnerHasher;
        type F = <C as GenericConfig<D>>::F;
        let rollup_constants: RollupConstants = RollupConstants {
            log_max_n_users: 3,
            log_max_n_txs: 3,
            log_max_n_contracts: 3,
            log_max_n_variables: 3,
            log_n_txs: 2,
            log_n_recipients: 3,
            log_n_contracts: 3,
            log_n_variables: 3,
            n_registrations: 2,
            n_diffs: 2,
            n_merges: 2,
            n_deposits: 2,
            n_blocks: 2,
        };
        let n_txs = 1 << rollup_constants.log_n_txs;
        let examples = make_sample_circuit_inputs::<C, D>(rollup_constants);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let approval_block_target = ApprovalBlockProductionTarget::add_virtual_to::<F, H, D>(
            &mut builder,
            rollup_constants.log_max_n_users,
            n_txs,
        );
        let circuit_data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        approval_block_target.set_witness::<F, D>(&mut pw, &examples[0].approval_block);

        println!("start proving: block_proof");
        let start = Instant::now();
        let proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        circuit_data.verify(proof).unwrap();
    }
}
