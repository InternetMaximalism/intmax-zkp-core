use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::{MerkleProof, MerkleProofTarget},
    },
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint};

use crate::{
    merkle_tree::gadgets::get_merkle_root_target,
    newspec::{
        common::{
            account::{Address, AddressTarget},
            asset::{Asset, AssetTarget},
            traits::{Leafable, LeafableTarget},
            transaction::{Transaction, TransactionTarget},
            user_state::{UserState, UserStateTarget},
        },
        utils::merkle_tree::merkle_tree::get_merkle_root,
    },
};

/// Assetの消去と、追加をbatchして行う処理
#[derive(Clone, Debug)]
pub struct PurgeTransition<F: RichField, H: AlgebraicHasher<F>> {
    pub sender_address: Address<F>,
    pub transaction: Transaction<F>,
    pub old_user_state: UserState<F>,
    pub token_index: usize,
    pub old_amount: BigUint,
    pub user_asset_inclusion_proof: MerkleProof<F, H>,
}

impl<F: RichField, H: AlgebraicHasher<F>> PurgeTransition<F, H> {
    /// Returns `(old_user_state_hash, new_user_state_hash, tx_hash)`
    pub fn calculate(&self) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>)> {
        let max_amount = BigUint::from_u8(1).unwrap() << 256;
        anyhow::ensure!(self.old_amount < max_amount);
        anyhow::ensure!(self.transaction.asset.amount <= self.old_amount);

        let old_asset = Asset {
            kind: self.transaction.asset.kind,
            amount: self.old_amount.clone(),
        };
        let calculated_old_asset_root = get_merkle_root(
            self.token_index,
            &old_asset,
            &self.user_asset_inclusion_proof,
        );
        anyhow::ensure!(calculated_old_asset_root == self.old_user_state.asset_root);

        let new_asset = Asset {
            kind: self.transaction.asset.kind,
            amount: self.old_amount.clone() - self.transaction.asset.amount.clone(),
        };
        let new_asset_root = get_merkle_root(
            self.token_index,
            &new_asset,
            &self.user_asset_inclusion_proof,
        );
        let new_user_state = UserState {
            asset_root: new_asset_root,
            nullifier_hash_root: self.old_user_state.nullifier_hash_root,
            public_key: self.old_user_state.public_key,
        };

        let old_user_state_hash = Leafable::<F, H>::hash(&self.old_user_state);
        let new_user_state_hash = Leafable::<F, H>::hash(&new_user_state);

        // TODO: validate sender_address

        let tx_hash = Leafable::<F, H>::hash(&self.transaction);

        Ok((old_user_state_hash, new_user_state_hash, tx_hash))
    }
}

#[derive(Clone, Debug)]
pub struct PurgeTransitionTarget {
    pub sender_address: AddressTarget,      // input
    pub transaction: TransactionTarget,     // input
    pub old_user_state: UserStateTarget,    // input
    pub token_index: Target,                // input
    pub old_amount: BigUintTarget,          // input
    pub old_user_state_hash: HashOutTarget, // output
    pub new_user_state_hash: HashOutTarget, // output

    /// user state tree における `transaction.asset` の inclusion proof
    pub user_asset_inclusion_proof: MerkleProofTarget, // input

    /// the hash of the `transaction`
    pub tx_hash: HashOutTarget, // output
}

impl PurgeTransitionTarget {
    #[allow(clippy::too_many_arguments)]
    pub fn make_constraints<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_max_n_kinds: usize,
    ) -> Self {
        let sender_address = AddressTarget::make_constraints(builder);
        let transaction = TransactionTarget::make_constraints(builder);
        let old_user_state = UserStateTarget::make_constraints(builder);
        let token_index = builder.add_virtual_target();
        let old_amount = builder.add_virtual_biguint_target(8);
        let user_asset_inclusion_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(log_max_n_kinds),
        };

        // TODO: assert!(self.transaction.asset.amount <= self.old_amount);

        let token_index_bits = builder.split_le(token_index, log_max_n_kinds);
        let old_asset_hash = LeafableTarget::<F, H, D>::hash(
            &AssetTarget {
                kind: transaction.asset.kind,
                amount: old_amount.clone(),
            },
            builder,
        );
        let calculated_old_asset_root = get_merkle_root_target::<F, H, D>(
            builder,
            &token_index_bits,
            old_asset_hash,
            &user_asset_inclusion_proof.siblings,
        );
        builder.connect_hashes(calculated_old_asset_root, old_user_state.asset_root);

        let new_amount = builder.sub_biguint(&old_amount, &transaction.asset.amount);
        let new_asset_hash = LeafableTarget::<F, H, D>::hash(
            &AssetTarget {
                kind: transaction.asset.kind,
                amount: new_amount,
            },
            builder,
        );
        let new_asset_root = get_merkle_root_target::<F, H, D>(
            builder,
            &token_index_bits,
            new_asset_hash,
            &user_asset_inclusion_proof.siblings,
        );
        let new_user_state = UserStateTarget {
            asset_root: new_asset_root,
            nullifier_hash_root: old_user_state.nullifier_hash_root,
            public_key: old_user_state.public_key,
        };

        let old_user_state_hash = LeafableTarget::<F, H, D>::hash(&old_user_state, builder);
        let new_user_state_hash = LeafableTarget::<F, H, D>::hash(&new_user_state, builder);

        // TODO: validate sender_address

        let tx_hash = LeafableTarget::<F, H, D>::hash(&transaction, builder);

        Self {
            sender_address,
            transaction,
            old_user_state,
            token_index,
            old_amount,
            old_user_state_hash,
            new_user_state_hash,
            user_asset_inclusion_proof,
            tx_hash,
        }
    }

    /// Returns (new_user_asset_root, tx_diff_root)
    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        purge_transition: &PurgeTransition<F, H>,
    ) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>)> {
        self.sender_address
            .set_witness(pw, purge_transition.sender_address);

        self.transaction
            .set_witness(pw, &purge_transition.transaction)?;
        self.old_user_state
            .set_witness(pw, purge_transition.old_user_state);
        pw.set_target(
            self.token_index,
            F::from_canonical_usize(purge_transition.token_index),
        );
        pw.set_biguint_target(&self.old_amount, &purge_transition.old_amount);

        anyhow::ensure!(
            self.user_asset_inclusion_proof.siblings.len()
                == purge_transition.user_asset_inclusion_proof.siblings.len()
        );
        for (target, value) in self
            .user_asset_inclusion_proof
            .siblings
            .iter()
            .zip(purge_transition.user_asset_inclusion_proof.siblings.iter())
        {
            pw.set_hash_target(*target, *value);
        }

        purge_transition.calculate()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::newspec::{
        client::{
            nullifier_hash_tree::NullifierHashTree,
            purge::{PurgeTransition, PurgeTransitionTarget},
            user_asset_tree::UserAssetTree,
        },
        common::{
            account::Address, traits::Leafable, transaction::Transaction, user_state::UserState,
        },
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

        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let target = PurgeTransitionTarget::make_constraints::<F, H, D>(
            &mut builder,
            LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES,
        );
        let data = builder.build::<C>();

        let user_asset_tree = UserAssetTree::<F, H>::new(LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES);
        let nullifier_hash_tree = NullifierHashTree::<F, H>::new(LOG_MAX_N_TXS);
        let public_key = HashOut::ZERO;
        let asset_root = user_asset_tree.merkle_tree.get_root();
        let token_index = 0;
        let user_asset_inclusion_proof = user_asset_tree.merkle_tree.prove(token_index);
        let old_asset = user_asset_tree.merkle_tree.get_leaf(token_index);
        let transaction = <Transaction<F> as Leafable<F, H>>::empty_leaf();
        let nullifier_hash_root = nullifier_hash_tree.merkle_tree.get_root();

        let purge_transaction = PurgeTransition {
            sender_address: Address::default(),
            transaction,
            old_user_state: UserState {
                asset_root,
                nullifier_hash_root,
                public_key,
            },
            token_index,
            old_amount: old_asset.amount,
            user_asset_inclusion_proof,
        };

        let mut pw = PartialWitness::new();
        target
            .set_witness::<F, H>(&mut pw, &purge_transaction)
            .unwrap();

        println!("start proving: default_proof");
        let start = Instant::now();
        let default_proof = data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        data.verify(default_proof).unwrap();
    }
}
