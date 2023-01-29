use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use crate::{
    merkle_tree::{gadgets::get_merkle_root_target, tree::KeyLike},
    transaction::{
        asset::ContributedAsset,
        gadgets::{
            asset_mess::ContributedAssetTarget,
            purge::{PurgeOutputProcessProof, PurgeOutputProcessProofTarget},
        },
        tree::tx_diff::TxDiffTree,
    },
    utils::gadgets::{
        hash::poseidon_two_to_one,
        logic::{conditionally_select, enforce_equal_if_enabled},
    },
};

#[allow(clippy::complexity)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositBlockProduction<F: RichField, H: Hasher<F>, K: KeyLike> {
    pub deposit_process_proofs: Vec<PurgeOutputProcessProof<F, H, K>>,
    pub log_n_recipients: usize,
    pub log_n_kinds: usize,
}

impl<F: RichField, H: Hasher<F>, K: KeyLike> DepositBlockProduction<F, H, K> {
    pub fn calculate(&self) -> anyhow::Result<H::Hash> {
        let deposit_tree =
            TxDiffTree::<_, H>::make_constraints(self.log_n_recipients, self.log_n_kinds);

        let mut prev_deposit_root = deposit_tree.get_root().unwrap();
        for process_proof in self.deposit_process_proofs.iter() {
            let (old_deposit_root, new_deposit_root) = process_proof.calculate();

            assert_eq!(old_deposit_root, prev_deposit_root);

            prev_deposit_root = new_deposit_root;
        }

        Ok(prev_deposit_root)
    }
}

#[derive(Clone, Debug)]
pub struct DepositBlockProductionTarget {
    pub deposit_process_proofs: Vec<PurgeOutputProcessProofTarget>, // input

    pub interior_deposit_digest: HashOutTarget, // output

    pub log_n_recipients: usize, // constant
    pub log_n_kinds: usize,      // constant
}

impl DepositBlockProductionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_n_recipients: usize,
        log_n_kinds: usize,
    ) -> Self {
        let n_levels = log_n_recipients + log_n_kinds;
        let n_deposits = 1 << n_levels;
        let deposit_process_proofs = (0..n_deposits)
            .map(|_| {
                PurgeOutputProcessProofTarget::make_constraints::<_, H, D>(
                    builder,
                    log_n_recipients,
                    log_n_kinds,
                )
            })
            .collect::<Vec<_>>();

        let default_asset_target = ContributedAssetTarget::constant_default(builder);
        let default_leaf_hash = builder.hash_n_to_hash_no_pad::<H>(default_asset_target.encode());

        let default_root_hash = {
            let mut default_root_hash = default_leaf_hash;
            for _ in 0..n_levels {
                default_root_hash =
                    poseidon_two_to_one::<_, H, D>(builder, default_root_hash, default_root_hash);
            }

            default_root_hash
        };

        let mut interior_deposit_digest = default_root_hash;
        for PurgeOutputProcessProofTarget {
            siblings: siblings_t,
            index: index_t,
            new_leaf_data: new_leaf_data_t,
            enabled: enabled_t,
        } in deposit_process_proofs.iter()
        {
            let proof1_old_leaf_t = default_leaf_hash;
            let proof1_new_leaf_t = builder.hash_n_to_hash_no_pad::<H>(new_leaf_data_t.encode());

            let proof1_old_root_t =
                get_merkle_root_target::<F, H, D>(builder, index_t, proof1_old_leaf_t, siblings_t);
            let proof1_new_root_t =
                get_merkle_root_target::<F, H, D>(builder, index_t, proof1_new_leaf_t, siblings_t);
            enforce_equal_if_enabled(
                builder,
                interior_deposit_digest,
                proof1_old_root_t,
                *enabled_t,
            );
            interior_deposit_digest = conditionally_select(
                builder,
                proof1_new_root_t,
                interior_deposit_digest,
                *enabled_t,
            );

            // deposit する asset の amount が 2^56 未満の値であること
            builder.range_check(new_leaf_data_t.amount, 56);
        }

        Self {
            deposit_process_proofs,
            interior_deposit_digest,
            log_n_recipients,
            log_n_kinds,
        }
    }

    /// Returns `interior_deposit_digest`
    pub fn set_witness<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        value: &DepositBlockProduction<F, H, Vec<bool>>,
    ) -> anyhow::Result<H::Hash> {
        for (target, value) in self
            .deposit_process_proofs
            .iter()
            .zip(value.deposit_process_proofs.iter())
        {
            target.set_witness::<_, H, Vec<bool>>(pw, value, true);
        }

        let default_leaf_data = ContributedAsset::default();
        for target in self
            .deposit_process_proofs
            .iter()
            .skip(value.deposit_process_proofs.len())
        {
            target.set_witness::<_, H, Vec<bool>>(
                pw,
                &PurgeOutputProcessProof {
                    // siblings: default_merkle_proof.siblings.clone(),
                    siblings: target
                        .siblings
                        .iter()
                        .map(|_| HashOut::ZERO)
                        .collect::<Vec<_>>(),
                    index: target.index.iter().map(|_| false).collect::<Vec<_>>(),
                    new_leaf_data: default_leaf_data,
                },
                false,
            );
        }

        value.calculate()
    }
}

// impl DepositBlockProductionTarget {
//     pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
//         builder: &mut CircuitBuilder<F, D>,
//         log_n_recipients: usize,
//         log_n_kinds: usize,
//     ) -> Self {
//         let n_level = log_n_recipients + log_n_kinds;
//         let n_deposits = 1 << n_level;
//         let deposit_list = (0..n_deposits)
//             .map(|_| ContributedAssetTarget::add_virtual_to(builder))
//             .collect::<Vec<_>>();

//         let leaves = deposit_list
//             .iter()
//             .map(|v| builder.hash_n_to_hash_no_pad::<H>(v.encode()))
//             .collect::<Vec<_>>();
//         let interior_deposit_digest =
//             get_merkle_root_target_from_leaves::<_, H, D>(builder, leaves);

//         Self {
//             deposit_list,
//             interior_deposit_digest,
//             log_n_recipients,
//             log_n_kinds,
//         }
//     }

//     /// Returns `interior_deposit_digest`
//     pub fn set_witness<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
//         &self,
//         pw: &mut impl Witness<F>,
//         value: &DepositBlockProduction<F>,
//     ) -> anyhow::Result<H::Hash> {
//         for (target, value) in self.deposit_list.iter().zip(value.deposit_list.iter()) {
//             target.set_witness(pw, *value);
//         }

//         for target in self.deposit_list.iter().skip(value.deposit_list.len()) {
//             target.set_witness(pw, ContributedAsset::default());
//         }

//         value.calculate::<H>()
//     }
// }

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        config::RollupConstants,
        rollup::{
            block::make_sample_circuit_inputs,
            gadgets::deposit_block::{DepositBlockProduction, DepositBlockProductionTarget},
        },
        transaction::{gadgets::purge::PurgeOutputProcessProof, tree::tx_diff::TxDiffTree},
    };

    #[test]
    fn test_deposit_block() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = <C as GenericConfig<D>>::InnerHasher;

        let rollup_constants = RollupConstants {
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
        let examples = make_sample_circuit_inputs::<C, D>(rollup_constants);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // deposit block
        let deposit_block_target = DepositBlockProductionTarget::add_virtual_to::<F, H, D>(
            &mut builder,
            rollup_constants.log_n_recipients,
            rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
        );
        builder.register_public_inputs(&deposit_block_target.interior_deposit_digest.elements);
        let circuit_data = builder.build::<C>();

        assert_eq!(circuit_data.common.degree_bits(), 15);

        let deposit_list = &examples[0].deposit_list;

        let mut tx_diff_tree = TxDiffTree::<F, H>::make_constraints(
            rollup_constants.log_n_recipients,
            rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
        );

        let mut deposit_process_proofs = vec![];
        for asset in deposit_list {
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

        let mut pw = PartialWitness::new();
        let deposit_process_proofs = DepositBlockProduction {
            deposit_process_proofs,
            log_n_recipients: rollup_constants.log_n_recipients,
            log_n_kinds: rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
        };
        let interior_deposit_digest = deposit_block_target
            .set_witness::<F, H, D>(&mut pw, &deposit_process_proofs)
            .unwrap();

        println!("start proving: deposit_block_proof");
        let start = Instant::now();
        let deposit_block_proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        assert_eq!(
            [interior_deposit_digest.elements].concat(),
            deposit_block_proof.public_inputs
        );

        circuit_data.verify(deposit_block_proof).unwrap();

        let mut pw = PartialWitness::new();
        let default_deposit_process_proofs = DepositBlockProduction {
            deposit_process_proofs: Default::default(),
            log_n_recipients: rollup_constants.log_n_recipients,
            log_n_kinds: rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
        };
        let default_interior_deposit_digest = deposit_block_target
            .set_witness::<F, H, D>(&mut pw, &default_deposit_process_proofs)
            .unwrap();

        println!("start proving: default_deposit_block_proof");
        let start = Instant::now();
        let default_deposit_block_proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        assert_eq!(
            [default_interior_deposit_digest.elements].concat(),
            default_deposit_block_proof.public_inputs
        );

        circuit_data.verify(default_deposit_block_proof).unwrap();
    }
}
