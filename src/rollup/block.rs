use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::{AlgebraicHasher, GenericConfig, Hasher},
};
use serde::{Deserialize, Serialize};

use crate::{
    config::RollupConstants,
    merkle_tree::tree::{get_merkle_proof, MerkleProcessProof, MerkleProof},
    rollup::address_list::TransactionSenderWithValidity,
    sparse_merkle_tree::{
        goldilocks_poseidon::{NodeDataMemory, PoseidonSparseMerkleTree, RootDataTmp},
        proof::{SparseMerkleInclusionProof, SparseMerkleProcessProof},
    },
    transaction::{
        asset::{ContributedAsset, TokenKind},
        block_header::{get_block_hash, BlockHeader},
        circuits::{MergeAndPurgeTransition, MergeAndPurgeTransitionPublicInputs},
        gadgets::{
            deposit_info::DepositInfo,
            merge::{DiffTreeInclusionProof, MergeProof},
            purge::{PurgeInputProcessProof, PurgeOutputProcessProof},
        },
        tree::{tx_diff::TxDiffTree, user_asset::UserAssetTree},
    },
    utils::hash::{GoldilocksHashOut, WrappedHashOut},
    zkdsa::{
        account::{private_key_to_account, Address},
        gadgets::signature::SimpleSignature,
    },
};

use super::gadgets::approval_block::ApprovalBlockProduction;

const LOG_MAX_N_BLOCKS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct BlockInfo<F: RichField> {
    #[serde(bound(
        serialize = "BlockHeader<F>: Serialize",
        deserialize = "BlockHeader<F>: Deserialize<'de>"
    ))]
    pub header: BlockHeader<F>,
    #[serde(bound(
        serialize = "WrappedHashOut<F>: Serialize",
        deserialize = "WrappedHashOut<F>: Deserialize<'de>"
    ))]
    pub transactions: Vec<WrappedHashOut<F>>,
    #[serde(bound(
        serialize = "DepositInfo<F>: Serialize",
        deserialize = "DepositInfo<F>: Deserialize<'de>"
    ))]
    pub deposit_list: Vec<DepositInfo<F>>,
    #[serde(bound(
        serialize = "TransactionSenderWithValidity<F>: Serialize",
        deserialize = "TransactionSenderWithValidity<F>: Deserialize<'de>"
    ))]
    pub address_list: Vec<TransactionSenderWithValidity<F>>,
    // diff_tree_proof
    // world_state_tree_proof
}

impl<F: RichField> BlockInfo<F> {
    pub fn new(log_num_txs_in_block: usize) -> Self {
        Self {
            header: BlockHeader::new(log_num_txs_in_block),
            transactions: Default::default(),
            deposit_list: Default::default(),
            address_list: Default::default(),
        }
    }
}

#[allow(clippy::complexity)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleBlock<F: RichField, H: AlgebraicHasher<F>> {
    pub transactions: Vec<(MergeAndPurgeTransition<F, H>, Option<SimpleSignature<F>>)>,
    pub old_world_state_root: HashOut<F>,
    pub world_state_process_proofs:
        Vec<SparseMerkleProcessProof<WrappedHashOut<F>, WrappedHashOut<F>, WrappedHashOut<F>>>,
    pub deposit_list: Vec<ContributedAsset<F>>,
    pub deposit_process_proofs: Vec<PurgeOutputProcessProof<F, H, Vec<bool>>>,
    pub approval_block: ApprovalBlockProduction<F>,
    pub block_headers_proof_siblings: Vec<HashOut<F>>,
    pub prev_block_header: BlockHeader<F>,
}

/// Returns `(stored_transactions, approval_block, new_world_root)`
pub fn make_sample_circuit_inputs<C: GenericConfig<D, F = GoldilocksField>, const D: usize>(
    rollup_constants: RollupConstants,
) -> Vec<SampleBlock<GoldilocksField, C::InnerHasher>> {
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
        amount: 2053,
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
        amount: 2053,
    };
    let asset4 = ContributedAsset {
        receiver_address: sender2_address,
        kind: TokenKind {
            contract_address: Address(GoldilocksHashOut::from_u128(471).0),
            variable_index: 8u8.into(),
        },
        amount: 1111,
    };

    let deposit_list = vec![asset1, asset2];

    let mut block0_deposit_tree = TxDiffTree::<_, C::InnerHasher>::new(
        rollup_constants.log_n_recipients,
        rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
    );
    block0_deposit_tree.insert(asset1).unwrap();
    block0_deposit_tree.insert(asset2).unwrap();

    // let merge_inclusion_root2 = block0_deposit_tree
    //     .get_asset_root(&sender2_address)
    //     .unwrap();

    // `deposit_tree` の root を `diff_root`, `hash(diff_root, nonce)` の値を `tx_hash` とよぶ.
    let deposit_nonce = HashOut::ZERO;
    let deposit_diff_root = block0_deposit_tree.get_root().unwrap();
    let deposit_tx_hash = PoseidonHash::two_to_one(deposit_diff_root, deposit_nonce);

    let diff_tree_inclusion_proof1 =
        get_merkle_proof::<_, C::InnerHasher>(&[deposit_tx_hash], 0, rollup_constants.log_n_txs);

    let diff_tree_inclusion_proof2 = block0_deposit_tree
        .prove_asset_root(&sender2_address)
        .unwrap();

    world_state_tree
        .set(
            sender2_address.0.into(),
            sender2_user_asset_tree.get_root().unwrap().into(),
        )
        .unwrap();

    let old_world_state_root = *world_state_tree.get_root().unwrap();

    let mut prev_block_header = BlockHeader::new(rollup_constants.log_n_txs);
    prev_block_header.block_number = 1;
    prev_block_header.deposit_digest = diff_tree_inclusion_proof1.root;
    prev_block_header.proposed_world_state_digest = old_world_state_root;
    prev_block_header.approved_world_state_digest = old_world_state_root;

    let prev_block_hash = get_block_hash(&prev_block_header);

    let mut block_headers: Vec<HashOut<GoldilocksField>> =
        vec![HashOut::ZERO; prev_block_header.block_number as usize];
    block_headers.push(prev_block_hash);

    // deposit の場合は, `hash(tx_hash, block_hash)` を `merge_key` とよぶ.
    let deposit_merge_key = PoseidonHash::two_to_one(deposit_tx_hash, prev_block_hash);

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

    let default_inclusion_proof = SparseMerkleInclusionProof::with_root(Default::default());
    let merge_proof = MergeProof {
        is_deposit: true,
        diff_tree_inclusion_proof,
        merge_process_proof,
        latest_account_tree_inclusion_proof: default_inclusion_proof,
        nonce: deposit_nonce,
    };

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

    // let old_world_state_root = *world_state_tree.get_root().unwrap();

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

    let prev_block_number = prev_block_header.block_number;
    let MerkleProof {
        siblings: block_headers_proof_siblings,
        ..
    } = get_merkle_proof::<_, PoseidonHash>(
        &block_headers,
        prev_block_number as usize,
        LOG_MAX_N_BLOCKS,
    );

    let mut tx_diff_tree = TxDiffTree::<C::F, C::InnerHasher>::new(
        rollup_constants.log_n_recipients,
        rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
    );

    let mut deposit_process_proofs = vec![];
    for asset in deposit_list.iter() {
        tx_diff_tree.insert(*asset).unwrap();
        let proof = tx_diff_tree
            .prove_leaf_node(&asset.receiver_address, &asset.kind)
            .unwrap();
        let process_proof = PurgeOutputProcessProof {
            siblings: proof.siblings,
            index: proof.index,
            new_leaf_data: *asset,
        };
        deposit_process_proofs.push(process_proof);
    }

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
        deposit_list,
        deposit_process_proofs,
        approval_block,
        block_headers_proof_siblings,
        prev_block_header,
    }]
}
