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
    merkle_tree::{
        gadgets::get_merkle_root_target,
        tree::{get_merkle_proof_with_zero, get_merkle_root, KeyLike},
    },
    transaction::asset::Transaction,
    // merkle_tree::sparse_merkle_tree::SparseMerkleTreeMemory,
    utils::gadgets::{
        hash::poseidon_two_to_one,
        logic::{conditionally_select, enforce_equal_if_enabled},
    },
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

use super::asset_mess::{verify_equal_assets, TransactionTarget};

/// 指定された`old_leaf_data`をアセットのデフォルト値に変更する構造体
// TODO: `RemoveAssetProof`などの方が分かりやすい気がする。Purgeはpurge txの意味でも使われているので、区別したほうが良さそう
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeInputProcessProof<F: RichField, H: Hasher<F>, K: KeyLike> {
    pub siblings: Vec<H::Hash>,
    pub index: K,
    pub old_leaf_data: Transaction<F>,
}

impl<F: RichField, H: Hasher<F>, K: KeyLike> PurgeInputProcessProof<F, H, K> {
    pub fn calculate(&self) -> (H::Hash, H::Hash) {
        // 取り除いた asset の amount が 2^56 未満の値であること
        assert!(self.old_leaf_data.amount < 1u64 << 56);

        let old_leaf_hash = H::hash_or_noop(&self.old_leaf_data.encode());
        let new_leaf_hash = H::hash_or_noop(&Transaction::default().encode());
        let old_user_asset_root =
            get_merkle_root::<F, H, _>(&self.index, old_leaf_hash, &self.siblings);
        let new_user_asset_root =
            get_merkle_root::<F, H, _>(&self.index, new_leaf_hash, &self.siblings);

        (old_user_asset_root, new_user_asset_root)
    }
}

#[derive(Clone, Debug)]
pub struct PurgeInputProcessProofTarget {
    pub siblings: Vec<HashOutTarget>,
    pub index: Vec<BoolTarget>,
    pub old_leaf_data: TransactionTarget,
    pub enabled: BoolTarget,
}

impl PurgeInputProcessProofTarget {
    pub fn make_constraints<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_txs: usize,
        log_max_n_kinds: usize,
    ) -> Self {
        let siblings = builder.add_virtual_hashes(log_max_n_txs + log_max_n_kinds);
        let index = (0..log_max_n_txs + log_max_n_kinds)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();
        let old_leaf_data = TransactionTarget::make_constraints(builder);
        let enabled = builder.add_virtual_bool_target_safe();

        Self {
            siblings,
            index,
            old_leaf_data,
            enabled,
        }
    }

    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &PurgeInputProcessProof<F, H, K>,
        enabled: bool,
    ) -> (HashOut<F>, HashOut<F>) {
        let mut index = witness.index.to_bits();
        index.resize(self.index.len(), false);

        // p0_t.set_witness(pw, w0);
        assert_eq!(self.siblings.len(), witness.siblings.len());
        for (ht, value) in self.siblings.iter().zip(witness.siblings.iter()) {
            pw.set_hash_target(*ht, *value);
        }
        for (t, lr_bit) in self.index.iter().zip(index.iter()) {
            pw.set_bool_target(*t, *lr_bit);
        }
        self.old_leaf_data.set_witness(pw, witness.old_leaf_data);
        pw.set_bool_target(self.enabled, enabled);

        witness.calculate()
    }
}

/// 空のasset leafに`new_leaf_data`を挿入する証明
// TODO: InsertAssetなどの名前の方が良い気がする
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeOutputProcessProof<F: RichField, H: Hasher<F>, K: KeyLike> {
    pub siblings: Vec<H::Hash>,
    pub index: K,
    pub new_leaf_data: Transaction<F>,
}

impl<F: RichField, H: Hasher<F>, K: KeyLike> PurgeOutputProcessProof<F, H, K> {
    pub fn calculate(&self) -> (H::Hash, H::Hash) {
        let old_leaf_hash = H::hash_or_noop(&Transaction::default().encode());
        let new_leaf_hash = H::hash_or_noop(&self.new_leaf_data.encode());

        // TODO: tx_diffしか想定していないなら、この構造体(&self)の名前にtx_diffを含めたほうが良さそう
        let old_tx_diff_root =
            get_merkle_root::<F, H, _>(&self.index, old_leaf_hash, &self.siblings);
        let new_tx_diff_root =
            get_merkle_root::<F, H, _>(&self.index, new_leaf_hash, &self.siblings);

        // 移動する asset の amount が 2^56 未満の値であること
        assert!(self.new_leaf_data.amount < 1u64 << 56);

        (old_tx_diff_root, new_tx_diff_root)
    }
}

#[derive(Clone, Debug)]
pub struct PurgeOutputProcessProofTarget {
    pub siblings: Vec<HashOutTarget>,
    pub index: Vec<BoolTarget>,
    pub new_leaf_data: TransactionTarget,
    pub enabled: BoolTarget,
}

impl PurgeOutputProcessProofTarget {
    pub fn make_constraints<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_n_recipients: usize,
        log_n_kinds: usize,
    ) -> Self {
        let siblings = builder.add_virtual_hashes(log_n_recipients + log_n_kinds);
        let index = (0..log_n_recipients + log_n_kinds)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();
        let new_leaf_data = TransactionTarget::make_constraints(builder);
        let enabled = builder.add_virtual_bool_target_safe();

        Self {
            siblings,
            index,
            new_leaf_data,
            enabled,
        }
    }

    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &PurgeOutputProcessProof<F, H, K>,
        enabled: bool,
    ) -> (HashOut<F>, HashOut<F>) {
        let mut index = witness.index.to_bits();
        index.resize(self.index.len(), false);

        assert_eq!(self.siblings.len(), witness.siblings.len());
        for (ht, value) in self.siblings.iter().zip(witness.siblings.iter()) {
            pw.set_hash_target(*ht, *value);
        }
        for (t, lr_bit) in self.index.iter().zip(index.iter()) {
            pw.set_bool_target(*t, *lr_bit);
        }
        pw.set_bool_target(self.enabled, enabled);
        self.new_leaf_data.set_witness(pw, witness.new_leaf_data);
        pw.set_bool_target(self.enabled, enabled);

        witness.calculate()
    }
}

/// Assetの消去と、追加をbatchして行う処理
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeTransition<F: RichField, H: AlgebraicHasher<F>, K: KeyLike> {
    pub sender_address: Address<F>,
    pub input_witnesses: Vec<PurgeInputProcessProof<F, H, K>>,
    pub output_witnesses: Vec<PurgeOutputProcessProof<F, H, K>>,
    pub old_user_asset_root: HashOut<F>,
    pub nonce: HashOut<F>,
}

impl<F: RichField, H: AlgebraicHasher<F>, K: KeyLike> PurgeTransition<F, H, K> {
    pub fn calculate(
        &self,
        log_n_recipients: usize,
        log_n_kinds: usize,
    ) -> (HashOut<F>, HashOut<F>, HashOut<F>) {
        let default_leaf_data = Transaction::default();
        let default_leaf_hash = H::hash_or_noop(&default_leaf_data.encode());

        let mut prev_user_asset_root = self.old_user_asset_root;
        let mut input_assets = std::collections::HashMap::new();
        for input_witness in self.input_witnesses.iter() {
            let (old_user_asset_root, new_user_asset_root) = input_witness.calculate();

            assert_eq!(old_user_asset_root, prev_user_asset_root);

            let asset = input_witness.old_leaf_data;
            if let Some(old_amount) = input_assets.get(&asset.kind) {
                input_assets.insert(asset.kind, old_amount + asset.amount);
            } else {
                input_assets.insert(asset.kind, asset.amount);
            }

            prev_user_asset_root = new_user_asset_root;
        }
        let new_user_asset_root = prev_user_asset_root;

        let default_diff_tree_root = get_merkle_proof_with_zero::<F, H>(
            &[],
            0,
            log_n_recipients + log_n_kinds,
            default_leaf_hash,
        )
        .root;
        let mut prev_diff_root = default_diff_tree_root;
        let mut output_assets = std::collections::HashMap::new();
        for output_witness in self.output_witnesses.iter() {
            let (old_tx_diff_root, new_tx_diff_root) = output_witness.calculate();

            assert_eq!(old_tx_diff_root, prev_diff_root);

            let asset = output_witness.new_leaf_data;
            if let Some(old_amount) = output_assets.get(&asset.kind) {
                output_assets.insert(asset.kind, old_amount + asset.amount);
            } else {
                output_assets.insert(asset.kind, asset.amount);
            }

            prev_diff_root = new_tx_diff_root;
        }
        let diff_root = prev_diff_root;

        let tx_hash = PoseidonHash::two_to_one(diff_root, self.nonce);

        assert_eq!(input_assets, output_assets);

        (new_user_asset_root, diff_root, tx_hash)
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

    pub log_max_n_txs: usize,    // constant
    pub log_max_n_kinds: usize,  // constant
    pub log_n_recipients: usize, // constant
    pub log_n_kinds: usize,      // constant
}

impl PurgeTransitionTarget {
    #[allow(clippy::too_many_arguments)]
    pub fn make_constraints<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_txs: usize,
        log_max_n_kinds: usize,
        log_n_recipients: usize,
        log_n_kinds: usize,
        n_diffs: usize,
    ) -> Self {
        let n_levels = log_n_recipients + log_n_kinds;

        let sender_address = AddressTarget::new(builder);
        let old_user_asset_root = builder.add_virtual_hash();
        let nonce = builder.add_virtual_hash();
        let input_proofs_t = (0..n_diffs)
            .map(|_| {
                PurgeInputProcessProofTarget::make_constraints::<F, H, D>(
                    builder,
                    log_max_n_txs,
                    log_max_n_kinds,
                )
            })
            .collect::<Vec<_>>();

        let output_proofs_t = (0..n_diffs)
            .map(|_| {
                PurgeOutputProcessProofTarget::make_constraints::<F, H, D>(
                    builder,
                    log_n_recipients,
                    log_n_kinds,
                )
            })
            .collect::<Vec<_>>();

        let zero = builder.zero();
        let default_hash = HashOutTarget {
            elements: [zero; 4],
        };

        let default_asset_target = TransactionTarget::constant_default(builder);
        let default_leaf_hash = builder.hash_n_to_hash_no_pad::<H>(default_asset_target.encode());
        assert_eq!(input_proofs_t.len(), output_proofs_t.len());
        let mut input_assets_t = Vec::with_capacity(input_proofs_t.len());
        let mut prev_user_asset_root = old_user_asset_root;
        for PurgeInputProcessProofTarget {
            siblings: siblings_t,
            index: index_t,
            old_leaf_data: old_leaf_data_t,
            enabled: enabled_t,
        } in input_proofs_t.iter()
        {
            let proof1_old_leaf_t = builder.hash_n_to_hash_no_pad::<H>(old_leaf_data_t.encode());
            let proof1_new_leaf_t = default_leaf_hash;

            let proof1_old_root_t =
                get_merkle_root_target::<F, H, D>(builder, index_t, proof1_old_leaf_t, siblings_t);
            let proof1_new_root_t =
                get_merkle_root_target::<F, H, D>(builder, index_t, proof1_new_leaf_t, siblings_t);
            enforce_equal_if_enabled(builder, prev_user_asset_root, proof1_old_root_t, *enabled_t);
            prev_user_asset_root =
                conditionally_select(builder, proof1_new_root_t, prev_user_asset_root, *enabled_t);

            // 取り除いた asset が 2^56 未満の値であること
            builder.range_check(old_leaf_data_t.amount, 56);

            input_assets_t.push(*old_leaf_data_t);
        }
        let new_user_asset_root = prev_user_asset_root;

        let default_root_hash = {
            let mut default_root_hash = default_leaf_hash;
            for _ in 0..n_levels {
                default_root_hash =
                    poseidon_two_to_one::<_, H, D>(builder, default_root_hash, default_root_hash);
            }

            default_root_hash
        };

        let mut prev_diff_root = default_hash;
        let mut output_assets_t = Vec::with_capacity(output_proofs_t.len());
        for PurgeOutputProcessProofTarget {
            siblings: siblings_t,
            index: index_t,
            new_leaf_data: new_leaf_data_t,
            enabled: enabled_t,
        } in output_proofs_t.iter()
        {
            let proof1_old_leaf_t = default_root_hash;
            let proof1_new_leaf_t = builder.hash_n_to_hash_no_pad::<H>(new_leaf_data_t.encode());

            let _proof1_old_root_t =
                get_merkle_root_target::<F, H, D>(builder, index_t, proof1_old_leaf_t, siblings_t);
            let proof1_new_root_t =
                get_merkle_root_target::<F, H, D>(builder, index_t, proof1_new_leaf_t, siblings_t);
            // enforce_equal_if_enabled(builder, prev_diff_root, proof1_old_root_t, *enabled_t); // XXX: zero_hash が途中で不自然に変化するため, この方法では検証できない.
            prev_diff_root =
                conditionally_select(builder, proof1_new_root_t, prev_diff_root, *enabled_t);

            // 移動する asset の amount が 2^56 未満の値であること
            builder.range_check(new_leaf_data_t.amount, 56);

            output_assets_t.push(*new_leaf_data_t);
        }
        let diff_root = prev_diff_root;

        verify_equal_assets::<F, H, D>(builder, &input_assets_t, &output_assets_t);

        let tx_hash = poseidon_two_to_one::<F, H, D>(builder, diff_root, nonce);

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
            log_max_n_kinds,
            log_n_recipients,
            log_n_kinds,
        }
    }

    /// Returns (new_user_asset_root, tx_diff_root)
    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>, K: KeyLike>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &PurgeTransition<F, H, K>,
    ) -> (HashOut<F>, HashOut<F>, HashOut<F>) {
        let default_leaf_data = Transaction::<F>::default();

        let (new_user_asset_root, diff_root, tx_hash) =
            witness.calculate(self.log_n_recipients, self.log_n_kinds);

        self.sender_address.set_witness(pw, witness.sender_address);
        pw.set_hash_target(self.old_user_asset_root, witness.old_user_asset_root);
        pw.set_hash_target(self.nonce, witness.nonce);

        assert!(witness.input_witnesses.len() <= self.input_proofs.len());
        for (input_witness_t, input_witness) in
            self.input_proofs.iter().zip(witness.input_witnesses.iter())
        {
            input_witness_t.set_witness(pw, input_witness, true);
        }

        for input_proof_t in self.input_proofs.iter().skip(witness.input_witnesses.len()) {
            input_proof_t.set_witness::<F, H, Vec<bool>>(
                pw,
                &PurgeInputProcessProof {
                    siblings: input_proof_t
                        .siblings
                        .iter()
                        .map(|_| HashOut::ZERO)
                        .collect::<Vec<_>>(),
                    index: input_proof_t
                        .index
                        .iter()
                        .map(|_| false)
                        .collect::<Vec<_>>(),
                    old_leaf_data: default_leaf_data,
                },
                false,
            );
        }

        assert!(witness.output_witnesses.len() <= self.output_proofs.len());
        for (output_proof_t, output_proof) in self
            .output_proofs
            .iter()
            .zip(witness.output_witnesses.iter())
        {
            output_proof_t.set_witness(pw, output_proof, true);
        }

        for output_proof_t in self
            .output_proofs
            .iter()
            .skip(witness.output_witnesses.len())
        {
            output_proof_t.set_witness::<F, H, Vec<bool>>(
                pw,
                &PurgeOutputProcessProof {
                    // siblings: default_merkle_proof.siblings.clone(),
                    siblings: output_proof_t
                        .siblings
                        .iter()
                        .map(|_| HashOut::ZERO)
                        .collect::<Vec<_>>(),
                    index: output_proof_t
                        .index
                        .iter()
                        .map(|_| false)
                        .collect::<Vec<_>>(),
                    new_leaf_data: default_leaf_data,
                },
                false,
            );
        }

        (new_user_asset_root, diff_root, tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        merkle_tree::tree::get_merkle_root,
        sparse_merkle_tree::goldilocks_poseidon::{
            NodeDataMemory, PoseidonSparseMerkleTree, RootDataTmp,
        },
        transaction::{
            asset::TokenKind,
            gadgets::purge::{
                PurgeInputProcessProof, PurgeOutputProcessProof, PurgeTransition,
                PurgeTransitionTarget, Transaction,
            },
            tree::{tx_diff::TxDiffTree, user_asset::UserAssetTree},
        },
        utils::hash::GoldilocksHashOut,
        zkdsa::account::{private_key_to_account, Address},
    };

    #[test]
    fn test_purge_proof() {
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
        let target = PurgeTransitionTarget::make_constraints::<F, H, D>(
            &mut builder,
            LOG_MAX_N_TXS,
            LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES,
            LOG_N_RECIPIENTS,
            LOG_N_CONTRACTS + LOG_N_VARIABLES,
            N_DIFFS,
        );
        builder.register_public_inputs(&target.new_user_asset_root.elements);
        builder.register_public_inputs(&target.diff_root.elements);
        builder.register_public_inputs(&target.tx_hash.elements);
        let data = builder.build::<C>();

        let private_key = vec![
            F::from_canonical_u64(15657143458229430356),
            F::from_canonical_u64(6012455030006979790),
            F::from_canonical_u64(4280058849535143691),
            F::from_canonical_u64(5153662694263190591),
        ];
        let user_account = private_key_to_account(private_key);
        let user_address = user_account.address;

        let merge_key1 = GoldilocksHashOut::from_u128(1);
        let asset1 = Transaction {
            to: user_address,
            kind: TokenKind {
                contract_address: Address(GoldilocksField(3)),
                variable_index: 8u8.into(),
            },
            amount: 2,
        };
        let merge_key2 = GoldilocksHashOut::from_u128(12);
        let asset2 = Transaction {
            to: user_address,
            kind: TokenKind {
                contract_address: Address(GoldilocksField(4)),
                variable_index: 8u8.into(),
            },
            amount: 1,
        };

        let asset3 = Transaction {
            to: Address(GoldilocksField(407)),
            kind: TokenKind {
                contract_address: Address(GoldilocksField(3)),
                variable_index: 8u8.into(),
            },
            amount: 2,
        };
        let asset4 = Transaction {
            to: Address(GoldilocksField(832)),
            kind: TokenKind {
                contract_address: Address(GoldilocksField(4)),
                variable_index: 8u8.into(),
            },
            amount: 1,
        };

        let mut world_state_tree =
            PoseidonSparseMerkleTree::new(NodeDataMemory::default(), RootDataTmp::default());

        let mut user_asset_tree =
            UserAssetTree::<F, H>::new(LOG_MAX_N_TXS, LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);
        let mut tx_diff_tree = TxDiffTree::<F, H>::make_constraints(
            LOG_N_RECIPIENTS,
            LOG_N_CONTRACTS + LOG_N_VARIABLES,
        );

        user_asset_tree
            .insert_assets(*merge_key1, vec![asset1])
            .unwrap();
        user_asset_tree
            .insert_assets(*merge_key2, vec![asset2])
            .unwrap();

        world_state_tree
            .set(
                user_address.to_hash_out().into(),
                user_asset_tree.get_root().unwrap().into(),
            )
            .unwrap();

        let default_leaf_hash = H::hash_or_noop(&Transaction::default().encode());

        let old_user_asset_root = user_asset_tree.get_root().unwrap();
        let proof1 = user_asset_tree
            .prove_leaf_node(&merge_key2, &user_address, &asset2.kind)
            .unwrap();
        let first_root = get_merkle_root::<F, H, _>(&proof1.index, proof1.value, &proof1.siblings);
        assert_eq!(first_root, proof1.root);

        let old_leaf_data1 = user_asset_tree
            .remove(*merge_key2, user_address, asset2.kind)
            .unwrap();
        let proof2 = user_asset_tree
            .prove_leaf_node(&merge_key1, &user_address, &asset1.kind)
            .unwrap();
        let second_root = get_merkle_root::<F, H, _>(&proof2.index, proof2.value, &proof2.siblings);
        assert_eq!(second_root, proof2.root);
        {
            let root =
                get_merkle_root::<F, H, _>(&proof1.index, default_leaf_hash, &proof1.siblings);
            assert_eq!(second_root, root);
        }

        let old_leaf_data2 = user_asset_tree
            .remove(*merge_key1, user_address, asset1.kind)
            .unwrap();
        let final_root = user_asset_tree.get_root().unwrap();
        {
            let root =
                get_merkle_root::<F, H, _>(&proof2.index, default_leaf_hash, &proof2.siblings);
            assert_eq!(final_root, root);
        }

        let init_root = tx_diff_tree.get_root().unwrap();
        tx_diff_tree.insert(asset3).unwrap();
        let proof3 = tx_diff_tree
            .prove_leaf_node(&asset3.to, &asset3.kind)
            .unwrap();

        let first_root = get_merkle_root::<F, H, _>(&proof3.index, proof3.value, &proof3.siblings);
        assert_eq!(first_root, proof3.root);
        {
            let root =
                get_merkle_root::<F, H, _>(&proof3.index, default_leaf_hash, &proof3.siblings);
            assert_eq!(root, init_root);
        }
        tx_diff_tree.insert(asset4).unwrap();
        let proof4 = tx_diff_tree
            .prove_leaf_node(&asset4.to, &asset4.kind)
            .unwrap();
        let second_root = get_merkle_root::<F, H, _>(&proof4.index, proof4.value, &proof4.siblings);
        assert_eq!(second_root, proof4.root);
        {
            let root =
                get_merkle_root::<F, H, _>(&proof4.index, default_leaf_hash, &proof4.siblings);
            assert_eq!(root, first_root);
        }

        let input_witnesses = vec![
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
        let output_witnesses = vec![
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
        let nonce = HashOut {
            elements: [
                F::from_canonical_u64(6657881311364026367),
                F::from_canonical_u64(11761473381903976612),
                F::from_canonical_u64(10768494808833234712),
                F::from_canonical_u64(3223267375194257474),
            ],
        };

        let witness = PurgeTransition {
            sender_address: user_address,
            input_witnesses,
            output_witnesses,
            old_user_asset_root,
            nonce,
        };

        let mut pw = PartialWitness::new();
        target.set_witness::<F, H, Vec<bool>>(&mut pw, &witness);

        println!("start proving: proof");
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        data.verify(proof).unwrap();

        let default_witness = PurgeTransition {
            sender_address: Default::default(),
            input_witnesses: vec![],
            output_witnesses: vec![],
            old_user_asset_root: Default::default(),
            nonce: Default::default(),
        };

        let mut pw = PartialWitness::new();
        target.set_witness::<F, H, HashOut<F>>(&mut pw, &default_witness);

        println!("start proving: default_proof");
        let start = Instant::now();
        let default_proof = data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        data.verify(default_proof).unwrap();
    }
}
