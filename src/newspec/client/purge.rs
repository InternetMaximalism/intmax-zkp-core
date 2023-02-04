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
            asset::{Asset, AssetTarget, AMOUNT_LIMBS},
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
    pub asset_id: usize,
    pub old_amount: BigUint,
    pub user_asset_inclusion_proof: MerkleProof<F, H>,
}

impl<F: RichField, H: AlgebraicHasher<F>> PurgeTransition<F, H> {
    /// Returns `(old_user_state_hash, new_user_state_hash, tx_hash)`
    pub fn calculate(&self) -> anyhow::Result<(HashOut<F>, HashOut<F>, HashOut<F>)> {
        let max_amount = BigUint::from_u8(1).unwrap() << (AMOUNT_LIMBS * 4);
        anyhow::ensure!(self.old_amount < max_amount);
        anyhow::ensure!(self.transaction.asset.amount <= self.old_amount);

        let old_asset = Asset {
            asset_id: self.transaction.asset.asset_id,
            amount: self.old_amount.clone(),
        };
        let calculated_old_asset_root =
            get_merkle_root(self.asset_id, &old_asset, &self.user_asset_inclusion_proof);
        anyhow::ensure!(calculated_old_asset_root == self.old_user_state.asset_root);

        let new_asset = Asset {
            asset_id: self.transaction.asset.asset_id,
            amount: self.old_amount.clone() - self.transaction.asset.amount.clone(),
        };
        let new_asset_root =
            get_merkle_root(self.asset_id, &new_asset, &self.user_asset_inclusion_proof);
        let new_user_state = UserState {
            asset_root: new_asset_root,
            nullifier_hash_root: self.old_user_state.nullifier_hash_root,
            public_key: self.old_user_state.public_key,
        };

        let old_user_state_hash = self.old_user_state.hash::<H>();
        let new_user_state_hash = new_user_state.hash::<H>();

        // TODO: validate sender_address

        let tx_hash = self.transaction.hash::<H>();

        Ok((old_user_state_hash, new_user_state_hash, tx_hash))
    }
}

#[derive(Clone, Debug)]
pub struct PurgeTransitionTarget {
    pub sender_address: AddressTarget,      // input
    pub transaction: TransactionTarget,     // input
    pub old_user_state: UserStateTarget,    // input
    pub asset_id: Target,                   // input
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
    pub fn new<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        asset_tree_height: usize,
    ) -> Self {
        let sender_address = AddressTarget::new(builder);
        let transaction = TransactionTarget::new(builder);
        let old_user_state = UserStateTarget::new(builder);
        let asset_id = builder.add_virtual_target();
        let old_amount = builder.add_virtual_biguint_target(AMOUNT_LIMBS);
        let user_asset_inclusion_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(asset_tree_height),
        };

        // TODO: assert!(self.transaction.asset.amount <= self.old_amount);

        let asset_id_bits = builder.split_le(asset_id, asset_tree_height);
        let old_asset_hash = AssetTarget {
            asset_id: transaction.asset.asset_id,
            amount: old_amount.clone(),
        }
        .hash::<F, H, D>(builder);
        let calculated_old_asset_root = get_merkle_root_target::<F, H, D>(
            builder,
            &asset_id_bits,
            old_asset_hash,
            &user_asset_inclusion_proof.siblings,
        );
        builder.connect_hashes(calculated_old_asset_root, old_user_state.asset_root);

        let new_amount = builder.sub_biguint(&old_amount, &transaction.asset.amount);
        let new_asset_hash = AssetTarget {
            asset_id: transaction.asset.asset_id,
            amount: new_amount,
        }
        .hash::<F, H, D>(builder);
        let new_asset_root = get_merkle_root_target::<F, H, D>(
            builder,
            &asset_id_bits,
            new_asset_hash,
            &user_asset_inclusion_proof.siblings,
        );
        let new_user_state = UserStateTarget {
            asset_root: new_asset_root,
            nullifier_hash_root: old_user_state.nullifier_hash_root,
            public_key: old_user_state.public_key,
        };

        let old_user_state_hash = old_user_state.hash::<F, H, D>(builder);
        let new_user_state_hash = new_user_state.hash::<F, H, D>(builder);

        // TODO: validate sender_address

        let tx_hash = transaction.hash::<F, H, D>(builder);

        Self {
            sender_address,
            transaction,
            old_user_state,
            asset_id,
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
            self.asset_id,
            F::from_canonical_usize(purge_transition.asset_id),
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
        let used_tx_hash_tree_height = 3;
        let asset_tree_height = 6;

        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let target = PurgeTransitionTarget::new::<F, H, D>(&mut builder, asset_tree_height);
        let data = builder.build::<C>();

        let user_asset_tree = UserAssetTree::<F, H>::new(asset_tree_height);
        let nullifier_hash_tree = NullifierHashTree::<F, H>::new(used_tx_hash_tree_height);
        let public_key = HashOut::ZERO;
        let asset_root = user_asset_tree.merkle_tree.get_root();
        let asset_id = 0;
        let user_asset_inclusion_proof = user_asset_tree.merkle_tree.prove(asset_id);
        let old_asset = user_asset_tree.merkle_tree.get_leaf(asset_id);
        let transaction = Transaction::empty_leaf();
        let nullifier_hash_root = nullifier_hash_tree.merkle_tree.get_root();

        let purge_transaction = PurgeTransition {
            sender_address: Address::default(),
            transaction,
            old_user_state: UserState {
                asset_root,
                nullifier_hash_root,
                public_key,
            },
            asset_id,
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
