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

use crate::newspec::common::account::{Address, AddressTarget};

use super::common::transaction::{
    ReceivedAmountProof, ReceivedAmountProofTarget, SentAmountProof, SentAmountProofTarget,
};

pub struct ReceivedAmountProofCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub target: ReceivedAmountProofTarget<D>,
    pub data: CircuitData<F, C, D>,
}

/// `account` received `total_amount_received` until `block`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedAmountProofPublicInputs<F: RichField> {
    pub account: Address,
    pub block_hash: HashOut<F>,
    pub total_amount_received_hash: HashOut<F>,
}

/// `account` received `total_amount_received` until `block`
#[derive(Clone, Debug)]
pub struct ReceivedAmountProofPublicInputsTarget {
    pub account: AddressTarget,
    pub block_hash: HashOutTarget,
    pub total_amount_received_hash: HashOutTarget,
}

impl ReceivedAmountProofPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let account = AddressTarget::new(builder);
        let block_hash = builder.add_virtual_hash();
        let total_amount_received_hash = builder.add_virtual_hash();

        Self {
            account,
            block_hash,
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
            self.account.to_vec(),
            self.block_hash.elements.to_vec(),
            self.total_amount_received_hash.elements.to_vec(),
        ]
        .concat()
    }

    pub fn from_vec(targets: &[Target]) -> Self {
        Self {
            account: AddressTarget(targets[0]),
            block_hash: HashOutTarget::from_vec(targets[1..5].to_vec()),
            total_amount_received_hash: HashOutTarget::from_vec(targets[5..9].to_vec()),
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
            account: target.account,
            block_hash: target.block_hash,
            total_amount_received_hash: target.total_amount_received_hash,
        };
        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();

        Self { target, data }
    }

    pub fn set_witness(
        &self,
        pw: &mut impl Witness<F>,
        witness: &ReceivedAmountProof<F, C, D>,
    ) -> anyhow::Result<ReceivedAmountProofPublicInputs<F>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let output = self.target.set_witness(pw, witness)?;

        Ok(ReceivedAmountProofPublicInputs {
            account: witness.account,
            block_hash: output.0,
            total_amount_received_hash: output.3,
        })
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;

        Ok(proof_with_pis)
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

/// `account` sent `total_amount_sent` until `block`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SentAmountProofPublicInputs<F: RichField> {
    pub account: Address,
    pub block_hash: HashOut<F>,
    pub total_amount_sent_hash: HashOut<F>,
}

/// `account` sent `total_amount_sent` until `block`
#[derive(Clone, Debug)]
pub struct SentAmountProofPublicInputsTarget {
    pub account: AddressTarget,
    pub block_hash: HashOutTarget,
    pub total_amount_sent_hash: HashOutTarget,
}

impl SentAmountProofPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let account = AddressTarget::new(builder);
        let block_hash = builder.add_virtual_hash();
        let total_amount_sent_hash = builder.add_virtual_hash();

        Self {
            account,
            block_hash,
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
            self.account.to_vec(),
            self.block_hash.elements.to_vec(),
            self.total_amount_sent_hash.elements.to_vec(),
        ]
        .concat()
    }

    pub fn from_vec(targets: &[Target]) -> Self {
        Self {
            account: AddressTarget(targets[0]),
            block_hash: HashOutTarget::from_vec(targets[1..5].to_vec()),
            total_amount_sent_hash: HashOutTarget::from_vec(targets[5..9].to_vec()),
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
        sent_amount_circuit_data: &CircuitData<F, C, D>,
        n_payments: usize,
        n_transfers: usize,
        transaction_tree_height: usize,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let target = SentAmountProofTarget::new::<F, C>(
            &mut builder,
            sent_amount_circuit_data,
            n_payments,
            n_transfers,
            transaction_tree_height,
        );
        let public_inputs = SentAmountProofPublicInputsTarget {
            account: target.account,
            block_hash: target.block_hash,
            total_amount_sent_hash: target.total_amount_sent_hash,
        };
        builder.register_public_inputs(&public_inputs.to_vec());
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
            account: witness.account,
            block_hash: output.0,
            total_amount_sent_hash: output.3,
        })
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;

        Ok(proof_with_pis)
    }
}
