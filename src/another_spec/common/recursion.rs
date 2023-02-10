use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

pub fn make_recursion_constraints<F, C, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inner_circuit_data: &CircuitData<F, C, D>,
) -> ProofWithPublicInputsTarget<D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    let proof_t = builder.add_virtual_proof_with_pis::<C>(&inner_circuit_data.common);
    let vd_target = builder.constant_verifier_data(&inner_circuit_data.verifier_only);
    builder.verify_proof::<C>(&proof_t, &vd_target, &inner_circuit_data.common);

    proof_t
}

#[derive(Clone)]
pub struct RecursiveProofTarget<const D: usize> {
    pub inner: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> RecursiveProofTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        circuit_data: &CircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let proof_t = make_recursion_constraints(builder, circuit_data);

        RecursiveProofTarget { inner: proof_t }
    }

    pub fn set_witness<F, C>(
        &self,
        pw: &mut impl Witness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_proof_with_pis_target(&self.inner, proof);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        field::types::Sample,
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        recursion::gadgets::RecursiveProofTarget, zkdsa::circuits::make_simple_signature_circuit,
        zkdsa::gadgets::signature::SimpleSignature,
    };

    #[test]
    fn test_recursion_simple_signature() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let private_key = HashOut::rand();
        let message = HashOut::rand();

        let config = CircuitConfig::standard_recursion_config();
        let zkdsa_circuit = make_simple_signature_circuit::<F, C, D>(config);

        let mut pw = PartialWitness::new();
        zkdsa_circuit.targets.set_witness(
            &mut pw,
            &SimpleSignature {
                private_key,
                message,
            },
        );

        println!("start proving: sender2_received_signature");
        let start = Instant::now();
        let signature = zkdsa_circuit.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        // proposal block
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let recursion_target =
            RecursiveProofTarget::add_virtual_to(&mut builder, &zkdsa_circuit.data);
        let circuit_data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        recursion_target.set_witness(
            &mut pw,
            &signature.into(),
            // &zkdsa_circuit.data.verifier_only,
            true,
        );

        println!("start proving: block_proof");
        let start = Instant::now();
        let proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        circuit_data.verify(proof).unwrap();
    }

    #[test]
    fn test_recursion_default_simple_signature() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let zkdsa_circuit = make_simple_signature_circuit::<F, C, D>(config);

        let mut pw = PartialWitness::new();
        zkdsa_circuit.targets.set_witness(
            &mut pw,
            &SimpleSignature {
                private_key: Default::default(),
                message: Default::default(),
            },
        );

        println!("start proving: sender2_received_signature");
        let start = Instant::now();
        let default_signature = zkdsa_circuit.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        // proposal block
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let recursion_target =
            RecursiveProofTarget::add_virtual_to(&mut builder, &zkdsa_circuit.data);
        let circuit_data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        recursion_target.set_witness(
            &mut pw,
            &default_signature.into(),
            // &zkdsa_circuit.verifier_only,
            false,
        );

        println!("start proving: block_proof");
        let start = Instant::now();
        let proof = circuit_data.prove(pw).unwrap();
        let end = start.elapsed();
        println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

        circuit_data.verify(proof).unwrap();
    }
}
