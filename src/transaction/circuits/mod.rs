use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{Proof, ProofWithPublicInputs},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    config::RollupConstants,
    transaction::gadgets::{
        merge::{MergeProof, MergeTransitionTarget},
        purge::PurgeTransitionTarget,
    },
    utils::{gadgets::hash::poseidon_two_to_one, hash::WrappedHashOut},
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

use super::gadgets::{
    merge::MergeTransition,
    purge::{PurgeInputProcessProof, PurgeOutputProcessProof, PurgeTransition},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeAndPurgeTransition<F: RichField, H: Hasher<F>> {
    pub sender_address: Address<F>,
    pub merge_witnesses: Vec<MergeProof<F, H, Vec<bool>>>,
    pub purge_input_witnesses: Vec<PurgeInputProcessProof<F, H, Vec<bool>>>,
    pub purge_output_witnesses: Vec<PurgeOutputProcessProof<F, H, Vec<bool>>>,
    pub nonce: HashOut<F>,
    pub old_user_asset_root: HashOut<F>,
}

impl<F: RichField, H: Hasher<F>> Default for MergeAndPurgeTransition<F, H> {
    fn default() -> Self {
        Self {
            sender_address: Default::default(),
            merge_witnesses: Default::default(),
            purge_input_witnesses: Default::default(),
            purge_output_witnesses: Default::default(),
            nonce: Default::default(),
            old_user_asset_root: Default::default(),
        }
    }
}

impl<F: RichField, H: AlgebraicHasher<F>> MergeAndPurgeTransition<F, H> {
    /// Returns `( middle_user_asset_root, new_user_asset_root, diff_root, tx_hash)`
    pub fn calculate(
        &self,
        log_n_recipients: usize,
        log_n_kinds: usize,
    ) -> (HashOut<F>, HashOut<F>, HashOut<F>, HashOut<F>) {
        let merge_witness = MergeTransition {
            proofs: self.merge_witnesses.clone(),
            old_user_asset_root: self.old_user_asset_root,
        };
        let middle_user_asset_root = merge_witness.calculate();
        let purge_transition = PurgeTransition {
            sender_address: self.sender_address,
            input_witnesses: self.purge_input_witnesses.clone(),
            output_witnesses: self.purge_output_witnesses.clone(),
            old_user_asset_root: middle_user_asset_root,
            nonce: self.nonce,
        };
        let (new_user_asset_root, diff_root, tx_hash) =
            purge_transition.calculate(log_n_recipients, log_n_kinds);

        (
            middle_user_asset_root,
            new_user_asset_root,
            diff_root,
            tx_hash,
        )
    }
}

pub struct MergeAndPurgeTransitionTarget {
    pub merge_proof_target: MergeTransitionTarget,
    pub purge_proof_target: PurgeTransitionTarget,
}

impl MergeAndPurgeTransitionTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        rollup_constants: RollupConstants,
    ) -> Self {
        let merge_proof_target: MergeTransitionTarget =
            MergeTransitionTarget::add_virtual_to::<F, H, D>(
                builder,
                rollup_constants.log_max_n_users,
                rollup_constants.log_max_n_txs,
                rollup_constants.log_n_txs,
                rollup_constants.log_n_recipients,
                rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
                rollup_constants.n_merges,
            );

        let purge_proof_target: PurgeTransitionTarget =
            PurgeTransitionTarget::make_constraints::<F, H, D>(
                builder,
                rollup_constants.log_max_n_txs,
                rollup_constants.log_max_n_contracts + rollup_constants.log_max_n_variables,
                rollup_constants.log_n_recipients,
                rollup_constants.log_n_contracts + rollup_constants.log_n_variables,
                rollup_constants.n_diffs,
            );
        builder.connect_hashes(
            merge_proof_target.new_user_asset_root,
            purge_proof_target.old_user_asset_root,
        );

        MergeAndPurgeTransitionTarget {
            merge_proof_target,
            purge_proof_target,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<F: RichField, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &MergeAndPurgeTransition<F, H>,
    ) -> MergeAndPurgeTransitionPublicInputs<F> {
        let merge_witness = MergeTransition {
            proofs: witness.merge_witnesses.clone(),
            old_user_asset_root: witness.old_user_asset_root,
        };
        let middle_user_asset_root = self
            .merge_proof_target
            .set_witness::<F, H, _>(pw, &merge_witness);
        let purge_transition = PurgeTransition {
            sender_address: witness.sender_address,
            input_witnesses: witness.purge_input_witnesses.clone(),
            output_witnesses: witness.purge_output_witnesses.clone(),
            old_user_asset_root: middle_user_asset_root,
            nonce: witness.nonce,
        };
        let (new_user_asset_root, diff_root, tx_hash) = self
            .purge_proof_target
            .set_witness::<F, H, _>(pw, &purge_transition);

        MergeAndPurgeTransitionPublicInputs {
            sender_address: witness.sender_address,
            old_user_asset_root: witness.old_user_asset_root.into(),
            middle_user_asset_root: middle_user_asset_root.into(),
            new_user_asset_root: new_user_asset_root.into(),
            diff_root: diff_root.into(),
            tx_hash: tx_hash.into(),
        }
    }
}

pub struct MergeAndPurgeTransitionCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub data: CircuitData<F, C, D>,
    pub targets: MergeAndPurgeTransitionTarget,
}

pub fn make_user_proof_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    rollup_constants: RollupConstants,
) -> MergeAndPurgeTransitionCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let targets = MergeAndPurgeTransitionTarget::add_virtual_to::<F, C::InnerHasher, D>(
        &mut builder,
        rollup_constants,
    );

    let tx_hash = poseidon_two_to_one::<F, C::InnerHasher, D>(
        &mut builder,
        targets.purge_proof_target.diff_root,
        targets.purge_proof_target.nonce,
    );

    let public_inputs = MergeAndPurgeTransitionPublicInputsTarget {
        sender_address: targets.purge_proof_target.sender_address,
        old_user_asset_root: targets.merge_proof_target.old_user_asset_root,
        middle_user_asset_root: targets.merge_proof_target.new_user_asset_root,
        new_user_asset_root: targets.purge_proof_target.new_user_asset_root,
        diff_root: targets.purge_proof_target.diff_root,
        tx_hash,
    };
    builder.register_public_inputs(&public_inputs.encode());

    let merge_and_purge_circuit_data = builder.build::<C>();

    MergeAndPurgeTransitionCircuit {
        data: merge_and_purge_circuit_data,
        targets,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct MergeAndPurgeTransitionPublicInputs<F: RichField> {
    pub sender_address: Address<F>,
    pub old_user_asset_root: WrappedHashOut<F>,
    pub middle_user_asset_root: WrappedHashOut<F>,
    pub new_user_asset_root: WrappedHashOut<F>,
    pub diff_root: WrappedHashOut<F>,
    pub tx_hash: WrappedHashOut<F>,
}

impl<F: RichField> Default for MergeAndPurgeTransitionPublicInputs<F> {
    fn default() -> Self {
        let diff_root = Default::default();
        let nonce = Default::default();
        let tx_hash = PoseidonHash::two_to_one(diff_root, nonce);

        Self {
            sender_address: Default::default(),
            old_user_asset_root: Default::default(),
            middle_user_asset_root: Default::default(),
            new_user_asset_root: Default::default(),
            diff_root: diff_root.into(),
            tx_hash: tx_hash.into(),
        }
    }
}

impl<F: RichField> MergeAndPurgeTransitionPublicInputs<F> {
    pub fn encode(&self) -> Vec<F> {
        let public_inputs = vec![
            self.old_user_asset_root.elements.to_vec(),
            self.middle_user_asset_root.elements.to_vec(),
            self.new_user_asset_root.elements.to_vec(),
            self.diff_root.elements.to_vec(),
            vec![self.sender_address.0],
            self.tx_hash.elements.to_vec(),
        ]
        .concat();
        assert_eq!(public_inputs.len(), 21);

        public_inputs
    }

    pub fn decode(public_inputs: &[F]) -> Self {
        assert_eq!(public_inputs.len(), 21);
        let old_user_asset_root = HashOut::from_partial(&public_inputs[0..4]).into();
        let middle_user_asset_root = HashOut::from_partial(&public_inputs[4..8]).into();
        let new_user_asset_root = HashOut::from_partial(&public_inputs[8..12]).into();
        let diff_root = HashOut::from_partial(&public_inputs[12..16]).into();
        let sender_address = Address(public_inputs[16]);
        let tx_hash = HashOut::from_partial(&public_inputs[17..21]).into();

        Self {
            old_user_asset_root,
            middle_user_asset_root,
            new_user_asset_root,
            diff_root,
            sender_address,
            tx_hash,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MergeAndPurgeTransitionPublicInputsTarget {
    pub sender_address: AddressTarget,
    pub old_user_asset_root: HashOutTarget,
    pub middle_user_asset_root: HashOutTarget,
    pub new_user_asset_root: HashOutTarget,
    pub diff_root: HashOutTarget,
    pub tx_hash: HashOutTarget,
}

impl MergeAndPurgeTransitionPublicInputsTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let sender_address = AddressTarget::new(builder);
        let old_user_asset_root = builder.add_virtual_hash();
        let middle_user_asset_root = builder.add_virtual_hash();
        let new_user_asset_root = builder.add_virtual_hash();
        let diff_root = builder.add_virtual_hash();
        let tx_hash = builder.add_virtual_hash();

        Self {
            sender_address,
            old_user_asset_root,
            middle_user_asset_root,
            new_user_asset_root,
            diff_root,
            tx_hash,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        public_inputs: &MergeAndPurgeTransitionPublicInputs<F>,
    ) {
        self.sender_address
            .set_witness(pw, public_inputs.sender_address);
        pw.set_hash_target(self.old_user_asset_root, *public_inputs.old_user_asset_root);
        pw.set_hash_target(
            self.middle_user_asset_root,
            *public_inputs.middle_user_asset_root,
        );
        pw.set_hash_target(self.new_user_asset_root, *public_inputs.new_user_asset_root);
        pw.set_hash_target(self.diff_root, *public_inputs.diff_root);
        pw.set_hash_target(self.tx_hash, *public_inputs.tx_hash);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) {
        builder.connect(a.sender_address.0, b.sender_address.0);
        builder.connect_hashes(a.old_user_asset_root, b.old_user_asset_root);
        builder.connect_hashes(a.middle_user_asset_root, b.middle_user_asset_root);
        builder.connect_hashes(a.new_user_asset_root, b.new_user_asset_root);
        builder.connect_hashes(a.diff_root, b.diff_root);
        builder.connect_hashes(a.tx_hash, b.tx_hash);
    }

    pub fn encode(&self) -> Vec<Target> {
        let public_inputs_t = vec![
            self.old_user_asset_root.elements.to_vec(),
            self.middle_user_asset_root.elements.to_vec(),
            self.new_user_asset_root.elements.to_vec(),
            self.diff_root.elements.to_vec(),
            vec![self.sender_address.0],
            self.tx_hash.elements.to_vec(),
        ]
        .concat();
        assert_eq!(public_inputs_t.len(), 21);

        public_inputs_t
    }

    pub fn decode(public_inputs_t: &[Target]) -> Self {
        assert_eq!(public_inputs_t.len(), 21);
        let old_user_asset_root = HashOutTarget {
            elements: public_inputs_t[0..4].try_into().unwrap(),
        };
        let middle_user_asset_root = HashOutTarget {
            elements: public_inputs_t[4..8].try_into().unwrap(),
        };
        let new_user_asset_root = HashOutTarget {
            elements: public_inputs_t[8..12].try_into().unwrap(),
        };
        let diff_root = HashOutTarget {
            elements: public_inputs_t[12..16].try_into().unwrap(),
        };
        let sender_address = AddressTarget(public_inputs_t[16]);
        let tx_hash = HashOutTarget {
            elements: public_inputs_t[17..21].try_into().unwrap(),
        };

        MergeAndPurgeTransitionPublicInputsTarget {
            sender_address,
            old_user_asset_root,
            middle_user_asset_root,
            new_user_asset_root,
            diff_root,
            tx_hash,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MergeAndPurgeTransitionProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: Proof<F, C, D>,
    pub public_inputs: MergeAndPurgeTransitionPublicInputs<F>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    From<MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>> for ProofWithPublicInputs<F, C, D>
{
    fn from(
        value: MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        ProofWithPublicInputs {
            proof: value.proof,
            public_inputs: value.public_inputs.encode(),
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    MergeAndPurgeTransitionCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn parse_public_inputs(&self) -> MergeAndPurgeTransitionPublicInputsTarget {
        let public_inputs_t = self.data.prover_only.public_inputs.clone();

        MergeAndPurgeTransitionPublicInputsTarget::decode(&public_inputs_t)
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;
        let public_inputs =
            MergeAndPurgeTransitionPublicInputs::decode(&proof_with_pis.public_inputs);

        Ok(MergeAndPurgeTransitionProofWithPublicInputs {
            proof: proof_with_pis.proof,
            public_inputs,
        })
    }

    pub fn set_witness_and_prove(
        &self,
        witness: &MergeAndPurgeTransition<F, C::InnerHasher>,
    ) -> anyhow::Result<MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        self.targets.set_witness(&mut pw, witness);

        self.prove(pw)
    }

    pub fn verify(
        &self,
        proof_with_pis: MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.data
            .verify(ProofWithPublicInputs::from(proof_with_pis))
    }
}

/// witness を入力にとり、 user_tx_proof を返す関数
pub fn prove_user_transaction<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rollup_constants: RollupConstants,
    witness: &MergeAndPurgeTransition<F, C::InnerHasher>,
) -> anyhow::Result<MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>>
where
    C::Hasher: AlgebraicHasher<F>,
{
    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let merge_and_purge_circuit = make_user_proof_circuit::<F, C, D>(config, rollup_constants);
    println!(
        "degree_bits: {}",
        merge_and_purge_circuit.data.common.degree_bits()
    );

    let mut pw = PartialWitness::new();
    let _public_inputs = merge_and_purge_circuit
        .targets
        .set_witness(&mut pw, witness);

    println!("start proving");
    let start = std::time::Instant::now();
    let user_tx_proof = merge_and_purge_circuit
        .prove(pw)
        .map_err(|err| anyhow::anyhow!("fail to prove user transaction: {}", err))?;
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    Ok(user_tx_proof)
}

#[cfg(test)]
mod tests {
    use plonky2::{hash::hash_types::HashOut, plonk::config::GenericConfig};

    use crate::{
        config::RollupConstants,
        transaction::circuits::{
            prove_user_transaction, MergeAndPurgeTransition, MergeAndPurgeTransitionPublicInputs,
        },
        utils::hash::WrappedHashOut,
    };

    #[test]
    fn test_prove_user_transaction() {
        use plonky2::plonk::config::PoseidonGoldilocksConfig;

        const LOG_MAX_N_USERS: usize = 16;
        const LOG_MAX_N_TXS: usize = 24;
        const LOG_MAX_N_CONTRACTS: usize = LOG_MAX_N_USERS;
        const LOG_MAX_N_VARIABLES: usize = 8;
        const LOG_N_TXS: usize = 4;
        const LOG_N_RECIPIENTS: usize = LOG_MAX_N_USERS;
        const LOG_N_CONTRACTS: usize = LOG_MAX_N_CONTRACTS;
        const LOG_N_VARIABLES: usize = LOG_MAX_N_VARIABLES;
        const N_REGISTRATIONS: usize = 16;
        const N_DEPOSITS: usize = 16;
        const N_MERGES: usize = 16;
        const N_DIFFS: usize = 16;
        const N_BLOCKS: usize = 4;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let rollup_constants: RollupConstants = RollupConstants {
            log_max_n_users: LOG_MAX_N_USERS,
            log_max_n_txs: LOG_MAX_N_TXS,
            log_max_n_contracts: LOG_MAX_N_CONTRACTS,
            log_max_n_variables: LOG_MAX_N_VARIABLES,
            log_n_txs: LOG_N_TXS,
            log_n_recipients: LOG_N_RECIPIENTS,
            log_n_contracts: LOG_N_CONTRACTS,
            log_n_variables: LOG_N_VARIABLES,
            n_registrations: N_REGISTRATIONS,
            n_diffs: N_DIFFS,
            n_merges: N_MERGES,
            n_deposits: N_DEPOSITS,
            n_blocks: N_BLOCKS,
        };

        let merge_and_purge_transition = MergeAndPurgeTransition::default();

        let _default_user_transaction_proof =
            prove_user_transaction::<F, C, D>(rollup_constants, &merge_and_purge_transition)
                .unwrap();
    }

    #[test]
    fn test_default_user_transaction() {
        use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

        type F = GoldilocksField;

        let default_user_transaction = MergeAndPurgeTransitionPublicInputs::<F>::default();

        let tx_hash = WrappedHashOut::from(HashOut {
            elements: [
                F::from_canonical_u64(4330397376401421145),
                F::from_canonical_u64(14124799381142128323),
                F::from_canonical_u64(8742572140681234676),
                F::from_canonical_u64(14345658006221440202),
            ],
        });

        assert_eq!(default_user_transaction.sender_address, Default::default());
        assert_eq!(
            default_user_transaction.old_user_asset_root,
            Default::default()
        );
        assert_eq!(
            default_user_transaction.middle_user_asset_root,
            Default::default()
        );
        assert_eq!(
            default_user_transaction.new_user_asset_root,
            Default::default()
        );
        assert_eq!(default_user_transaction.diff_root, Default::default());
        assert_eq!(default_user_transaction.tx_hash, tx_hash);
    }
}
