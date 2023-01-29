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
        sparse_merkle_tree::Leafable,
        tree::{get_merkle_proof_with_zero, get_merkle_root, KeyLike, MerkleProcessProof},
    },
    transaction::{
        asset::{Asset, Transaction},
        tree::tx_diff::TransactionWithNullifier,
    },
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

        let old_leaf_hash = self.old_leaf_data.hash();
        let new_leaf_hash = Transaction::default().hash();
        let old_user_asset_root =
            get_merkle_root::<F, H, _, _>(&self.index, old_leaf_hash, &self.siblings);
        let new_user_asset_root =
            get_merkle_root::<F, H, _, _>(&self.index, new_leaf_hash, &self.siblings);

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
    pub new_leaf_data: TransactionWithNullifier<F, H>,
}

impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>, K: KeyLike> PurgeOutputProcessProof<F, H, K> {
    pub fn calculate(&self) -> (H::Hash, H::Hash) {
        let old_leaf_hash = TransactionWithNullifier::<F, H>::default().hash();
        let new_leaf_hash = self.new_leaf_data.hash();

        // TODO: tx_diffしか想定していないなら、この構造体(&self)の名前にtx_diffを含めたほうが良さそう
        let old_tx_diff_root =
            get_merkle_root::<F, H, _, _>(&self.index, old_leaf_hash, &self.siblings);
        let new_tx_diff_root =
            get_merkle_root::<F, H, _, _>(&self.index, new_leaf_hash, &self.siblings);

        // 移動する asset の amount が 2^56 未満の値であること
        assert!(self.new_leaf_data.transaction.amount < 1u64 << 56);

        (old_tx_diff_root, new_tx_diff_root)
    }
}

#[derive(Clone, Debug)]
pub struct PurgeOutputProcessProofTarget {
    pub siblings: Vec<HashOutTarget>,
    pub index: Vec<BoolTarget>,
    pub new_leaf_data: TransactionTarget,
    pub nullifier: HashOutTarget,
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
        let nullifier = builder.add_virtual_hash();
        let enabled = builder.add_virtual_bool_target_safe();

        Self {
            siblings,
            index,
            new_leaf_data,
            nullifier,
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
        self.new_leaf_data
            .set_witness(pw, witness.new_leaf_data.transaction);
        pw.set_hash_target(self.nullifier, witness.new_leaf_data.nullifier);
        pw.set_bool_target(self.enabled, enabled);

        witness.calculate()
    }
}

/// Assetの消去と、追加をbatchして行う処理
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeTransition<F: RichField, H: AlgebraicHasher<F>> {
    pub from: Address<F>,
    pub to: Address<F>,
    pub process_proof: MerkleProcessProof<F, H, usize, Asset<F>>,
    pub nullifier: HashOut<F>,
}

impl<F: RichField, H: AlgebraicHasher<F>> PurgeTransition<F, H> {
    pub fn calculate(
        &self,
        log_n_recipients: usize,
        log_n_kinds: usize,
    ) -> (HashOut<F>, HashOut<F>, TransactionWithNullifier<F, H>) {
        let default_leaf_data = Transaction::default();
        let default_leaf_hash = H::hash_or_noop(&default_leaf_data.encode());

        let (old_user_asset_root, new_user_asset_root) = self.process_proof.calculate();

        let diff_amount = self.process_proof.new_value.amount - self.process_proof.old_value.amount;

        let transaction = TransactionWithNullifier {
            transaction: Transaction {
                to: self.to,
                kind: self.process_proof.new_value.kind,
                amount: diff_amount,
            },
            nullifier: self.nullifier,
        };

        (old_user_asset_root, new_user_asset_root, transaction)
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
            builder.range_check(old_leaf_data_t.amount.0, 56);

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
            builder.range_check(new_leaf_data_t.amount.0, 56);

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
    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &PurgeTransition<F, H>,
    ) -> (HashOut<F>, HashOut<F>, HashOut<F>) {
        let default_leaf_data = Transaction::<F>::default();

        let (new_user_asset_root, diff_root, tx_hash) =
            witness.calculate(self.log_n_recipients, self.log_n_kinds);

        self.sender_address.set_witness(pw, witness.from);
        // pw.set_hash_target(self.old_user_asset_root, witness.old_user_asset_root);
        pw.set_hash_target(self.nonce, witness.nullifier);

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
        merkle_tree::{
            sparse_merkle_tree::SparseMerkleTreeMemory,
            tree::{get_merkle_root, MerkleProcessProof},
        },
        // sparse_merkle_tree::goldilocks_poseidon::{
        //     NodeDataMemory, PoseidonSparseMerkleTree, RootDataTmp,
        // },
        transaction::{
            asset::{Asset, TokenKind},
            gadgets::purge::{
                PurgeInputProcessProof, PurgeOutputProcessProof, PurgeTransition,
                PurgeTransitionTarget, Transaction,
            },
            tree::{tx_diff::TxDiffTree, user_asset::UserAssetTree},
        },
        utils::hash::{GoldilocksHashOut, WrappedHashOut},
        zkdsa::account::{private_key_to_account, Address},
    };

    #[test]
    fn test_purge_proof() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type H = <C as GenericConfig<D>>::InnerHasher;
        type F = <C as GenericConfig<D>>::F;
        const LOG_MAX_N_USERS: usize = 3;
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

        let merge_key1 = *GoldilocksHashOut::from_u128(1);
        let asset1 = Asset {
            kind: TokenKind {
                contract_address: Address(GoldilocksField(3)),
                variable_index: 8u8.into(),
            },
            amount: 2,
        };
        let merge_key2 = *GoldilocksHashOut::from_u128(12);
        let asset2 = Asset {
            kind: TokenKind {
                contract_address: Address(GoldilocksField(4)),
                variable_index: 8u8.into(),
            },
            amount: 1,
        };
        let recipient = Address(GoldilocksField(832));
        let asset = Transaction {
            to: recipient,
            kind: TokenKind {
                contract_address: Address(GoldilocksField(3)),
                variable_index: 8u8.into(),
            },
            amount: 1,
        };

        let mut world_state_tree: SparseMerkleTreeMemory<F, H, WrappedHashOut<F>> =
            SparseMerkleTreeMemory::new(LOG_MAX_N_USERS);

        let mut user_asset_tree =
            UserAssetTree::<F, H>::new(LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);

        user_asset_tree.add(asset1);
        user_asset_tree.add(asset2);

        world_state_tree.insert(
            &user_address.to_hash_out(),
            user_asset_tree.get_root().into(),
        );

        let default_leaf_hash = H::hash_or_noop(&Transaction::default().encode());

        let old_user_asset_root = user_asset_tree.get_root();
        let process_proof = user_asset_tree.sub(&asset);
        let nullifier = HashOut {
            elements: [
                F::from_canonical_u64(6657881311364026367),
                F::from_canonical_u64(11761473381903976612),
                F::from_canonical_u64(10768494808833234712),
                F::from_canonical_u64(3223267375194257474),
            ],
        };

        let witness = PurgeTransition {
            from: user_address,
            to: recipient,
            process_proof,
            nullifier,
        };

        let mut pw = PartialWitness::new();
        target.set_witness::<F, H>(&mut pw, &witness);

        println!("start proving: proof");
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        data.verify(proof).unwrap();

        let default_witness = PurgeTransition {
            from: Default::default(),
            to: Default::default(),
            process_proof: Default::default(),
            nullifier: Default::default(),
        };

        let mut pw = PartialWitness::new();
        target.set_witness::<F, H>(&mut pw, &default_witness);

        println!("start proving: default_proof");
        let start = Instant::now();
        let default_proof = data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        data.verify(default_proof).unwrap();
    }
}
