use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::{MerkleProof, MerkleProofTarget},
    },
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

use crate::{
    merkle_tree::tree::KeyLike,
    newspec::common::transaction::{Transaction, TransactionTarget},
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

/// Assetの消去と、追加をbatchして行う処理
#[derive(Clone, Debug)]
pub struct PurgeTransition<F: RichField, H: AlgebraicHasher<F>> {
    pub sender_address: Address<F>,
    pub transaction: Transaction<F>,
    pub old_amount: BigUint,
    pub old_user_asset_root: HashOut<F>,
    pub user_asset_inclusion_proof: MerkleProof<F, H>,
}

impl<F: RichField, H: AlgebraicHasher<F>> PurgeTransition<F, H> {
    pub fn calculate(&self) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct PurgeTransitionTarget {
    pub sender_address: AddressTarget,      // input
    pub transaction: TransactionTarget,     // input
    pub old_amount: BigUintTarget,          // input
    pub old_user_state_root: HashOutTarget, // output
    pub new_user_state_root: HashOutTarget, // output

    /// user state tree における `transaction.asset` の inclusion proof
    pub user_asset_inclusion_proof: MerkleProofTarget, // input

    /// the hash of the `transaction`
    pub tx_hash: HashOutTarget, // output
}

impl PurgeTransitionTarget {
    #[allow(clippy::too_many_arguments)]
    pub fn make_constraints<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        todo!()
    }

    /// Returns (new_user_asset_root, tx_diff_root)
    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>, K: KeyLike>(
        &self,
        _pw: &mut impl Witness<F>,
        _purge_transition: &PurgeTransition<F, H>,
    ) {
        // TODO: transaction.amount <= old_amount

        // TODO: new_amount <- old_amount - transaction.amount

        // TODO: validate (user_asset_inclusion_proof, old_amount, transaction.asset.kind, old_user_state_root)

        // TODO: validate (user_asset_inclusion_proof, new_amount, transaction.asset.kind, new_user_state_root)

        // TODO: transaction.amount < MAX_AMOUNT

        // TODO: tx_hash <- transaction.hash()

        // TODO: validate sender_address

        // TODO: old_user_state_root <- old_user_state.hash()

        // TODO: new_user_state_root <- new_user_state.hash()

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        hash::{hash_types::HashOut, merkle_proofs::MerkleProof},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::newspec::client::purge::{PurgeTransition, PurgeTransitionTarget};

    #[test]
    fn test_purge_proof() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type H = <C as GenericConfig<D>>::InnerHasher;
        type F = <C as GenericConfig<D>>::F;
        // const LOG_MAX_N_TXS: usize = 3;
        const LOG_MAX_N_CONTRACTS: usize = 3;
        const LOG_MAX_N_VARIABLES: usize = 3;
        // const LOG_N_RECIPIENTS: usize = 3;
        // const LOG_N_CONTRACTS: usize = 3;
        // const LOG_N_VARIABLES: usize = 3;
        // const N_DIFFS: usize = 2;

        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let target = PurgeTransitionTarget::make_constraints::<F, H, D>(&mut builder);
        let data = builder.build::<C>();

        let default_witness = PurgeTransition {
            sender_address: Default::default(),
            transaction: Default::default(),
            old_amount: Default::default(),
            old_user_asset_root: Default::default(),
            user_asset_inclusion_proof: MerkleProof {
                siblings: vec![Default::default(); LOG_MAX_N_CONTRACTS + LOG_MAX_N_VARIABLES],
            },
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
