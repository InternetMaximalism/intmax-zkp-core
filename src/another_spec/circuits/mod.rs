use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::common::transaction::{
    ReceivedAmountProofTarget, SentAmountProof, SentAmountProofTarget,
};

pub struct ReceivedAmountProofCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub target: ReceivedAmountProofTarget<D>,
    pub data: CircuitData<F, C, D>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedAmountProofPublicInputs<F: RichField> {
    pub last_block_hash: HashOut<F>,
    pub amount_received_before_last_block_hash: HashOut<F>,
    pub amount_received_in_last_block_hash: HashOut<F>,
    pub total_amount_received_hash: HashOut<F>,
}

#[derive(Clone, Debug)]
pub struct ReceivedAmountProofPublicInputsTarget {
    pub last_block_hash: HashOutTarget,
    pub amount_received_before_last_block_hash: HashOutTarget,
    pub amount_received_in_last_block_hash: HashOutTarget,
    pub total_amount_received_hash: HashOutTarget,
}

impl ReceivedAmountProofPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let last_block_hash = builder.add_virtual_hash();
        let amount_received_before_last_block_hash = builder.add_virtual_hash();
        let amount_received_in_last_block_hash = builder.add_virtual_hash();
        let total_amount_received_hash = builder.add_virtual_hash();

        Self {
            last_block_hash,
            amount_received_before_last_block_hash,
            amount_received_in_last_block_hash,
            total_amount_received_hash,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        _pw: &mut impl Witness<F>,
        _witness: ReceivedAmountProofPublicInputs<F>,
    ) {
        todo!()
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.last_block_hash.elements.to_vec(),
            self.amount_received_before_last_block_hash
                .elements
                .to_vec(),
            self.amount_received_in_last_block_hash.elements.to_vec(),
            self.total_amount_received_hash.elements.to_vec(),
        ]
        .concat()
    }

    pub fn from_vec(targets: &[Target]) -> Self {
        Self {
            last_block_hash: HashOutTarget::from_vec(targets[0..4].to_vec()),
            amount_received_before_last_block_hash: HashOutTarget::from_vec(targets[4..8].to_vec()),
            amount_received_in_last_block_hash: HashOutTarget::from_vec(targets[8..12].to_vec()),
            total_amount_received_hash: HashOutTarget::from_vec(targets[12..16].to_vec()),
        }
    }

    pub fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_or_noop::<H>(self.to_vec())
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceivedAmountProofCircuit<F, C, D>
{
    pub fn new(
        config: CircuitConfig,
        received_amount_circuit_data: &CircuitData<F, C, D>,
        sent_amount_circuit_data: &CircuitData<F, C, D>,
        n_payments: usize,
        transaction_tree_height: usize,
        transfer_tree_height: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let target = ReceivedAmountProofTarget::new::<F, C>(
            &mut builder,
            received_amount_circuit_data,
            sent_amount_circuit_data,
            n_payments,
            transaction_tree_height,
            transfer_tree_height,
        );
        let public_inputs = ReceivedAmountProofPublicInputsTarget {
            last_block_hash: target.last_block_hash,
            amount_received_before_last_block_hash: target.amount_received_before_last_block_hash,
            amount_received_in_last_block_hash: target.amount_received_in_last_block_hash,
            total_amount_received_hash: target.total_amount_received_hash,
        };
        let entry_hash = public_inputs.hash::<F, C::Hasher, D>(&mut builder);
        builder.register_public_inputs(&entry_hash.elements);
        let data = builder.build::<C>();

        Self { target, data }
    }
}

pub struct SentAmountProofCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub target: SentAmountProofTarget<D>,
    pub data: CircuitData<F, C, D>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SentAmountProofPublicInputs<F: RichField> {
    pub last_block_hash: HashOut<F>,
    pub amount_sent_before_last_block_hash: HashOut<F>,
    pub amount_sent_in_last_block_hash: HashOut<F>,
    pub total_amount_sent_hash: HashOut<F>,
}

#[derive(Clone, Debug)]
pub struct SentAmountProofPublicInputsTarget {
    pub last_block_hash: HashOutTarget,
    pub amount_sent_before_last_block_hash: HashOutTarget,
    pub amount_sent_in_last_block_hash: HashOutTarget,
    pub total_amount_sent_hash: HashOutTarget,
}

impl SentAmountProofPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let last_block_hash = builder.add_virtual_hash();
        let amount_sent_before_last_block_hash = builder.add_virtual_hash();
        let amount_sent_in_last_block_hash = builder.add_virtual_hash();
        let total_amount_sent_hash = builder.add_virtual_hash();

        Self {
            last_block_hash,
            amount_sent_before_last_block_hash,
            amount_sent_in_last_block_hash,
            total_amount_sent_hash,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        _pw: &mut impl Witness<F>,
        _witness: SentAmountProofPublicInputs<F>,
    ) {
        todo!()
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.last_block_hash.elements.to_vec(),
            self.amount_sent_before_last_block_hash.elements.to_vec(),
            self.amount_sent_in_last_block_hash.elements.to_vec(),
            self.total_amount_sent_hash.elements.to_vec(),
        ]
        .concat()
    }

    pub fn from_vec(targets: &[Target]) -> Self {
        Self {
            last_block_hash: HashOutTarget::from_vec(targets[0..4].to_vec()),
            amount_sent_before_last_block_hash: HashOutTarget::from_vec(targets[4..8].to_vec()),
            amount_sent_in_last_block_hash: HashOutTarget::from_vec(targets[8..12].to_vec()),
            total_amount_sent_hash: HashOutTarget::from_vec(targets[12..16].to_vec()),
        }
    }

    pub fn hash<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_or_noop::<H>(self.to_vec())
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SentAmountProofCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        config: CircuitConfig,
        inner_circuit_data: &CircuitData<F, C, D>,
        n_payments: usize,
        n_transfers: usize,
        transaction_tree_height: usize,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // let last_sent_amount_proof = SentAmountProofPublicInputsTarget::from_vec(
        //     inner_circuit_data.prover_only.public_inputs,
        // );
        let target = SentAmountProofTarget::new::<F, C>(
            &mut builder,
            inner_circuit_data,
            n_payments,
            n_transfers,
            transaction_tree_height,
        );
        let public_inputs = SentAmountProofPublicInputsTarget {
            last_block_hash: target.last_block_hash,
            amount_sent_before_last_block_hash: target.amount_sent_before_last_block_hash,
            amount_sent_in_last_block_hash: target.amount_sent_in_last_block_hash,
            total_amount_sent_hash: target.total_amount_sent_hash,
        };
        let entry_hash = public_inputs.hash::<F, C::InnerHasher, D>(&mut builder);
        builder.register_public_inputs(&entry_hash.elements);
        let data = builder.build::<C>();

        Self { target, data }
    }

    pub fn set_witness(
        &self,
        pw: &mut impl Witness<F>,
        witness: &SentAmountProof<F, C, D>,
    ) -> anyhow::Result<SentAmountProofPublicInputs<F>> {
        let output = self.target.set_witness(pw, witness)?;

        Ok(SentAmountProofPublicInputs {
            last_block_hash: output.0,
            amount_sent_before_last_block_hash: output.1,
            amount_sent_in_last_block_hash: output.2,
            total_amount_sent_hash: output.3,
        })
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;
        // if proof_with_pis.public_inputs.len() != 4 {
        //     anyhow::bail!("invalid length of public inputs");
        // }
        // let entry_hash = HashOut::from_partial(&proof_with_pis.public_inputs[..4]);
        // if entry_hash != public_inputs.hash() {
        //     anyhow::bail!("invalid entry hash");
        // }

        Ok(proof_with_pis)
    }
}
