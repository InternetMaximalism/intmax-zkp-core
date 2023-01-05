use plonky2::{
    field::extension::Extendable,
    fri::proof::FriProofTarget,
    gadgets::polynomial::PolynomialCoeffsExtTarget,
    hash::hash_types::{MerkleCapTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofTarget, ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Wrapper<T>(pub T);

impl<T> std::ops::Deref for Wrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone)]
pub struct RecursiveProofTarget<const D: usize> {
    pub inner: Wrapper<ProofWithPublicInputsTarget<D>>,
    pub verifier_only_data: VerifierCircuitTarget,
    pub enabled: BoolTarget,
}

impl<const D: usize> Clone for Wrapper<ProofWithPublicInputsTarget<D>> {
    fn clone(&self) -> Self {
        Wrapper(ProofWithPublicInputsTarget {
            proof: ProofTarget {
                wires_cap: self.0.proof.wires_cap.clone(),
                plonk_zs_partial_products_cap: self.0.proof.plonk_zs_partial_products_cap.clone(),
                quotient_polys_cap: self.0.proof.quotient_polys_cap.clone(),
                openings: self.0.proof.openings.clone(),
                opening_proof: FriProofTarget {
                    commit_phase_merkle_caps: self
                        .0
                        .proof
                        .opening_proof
                        .commit_phase_merkle_caps
                        .clone(),
                    query_round_proofs: self.0.proof.opening_proof.query_round_proofs.clone(),
                    final_poly: PolynomialCoeffsExtTarget(
                        self.0.proof.opening_proof.final_poly.0.clone(),
                    ),
                    pow_witness: self.0.proof.opening_proof.pow_witness,
                },
            },
            public_inputs: self.0.public_inputs.clone(),
        })
    }
}

// impl Clone for Wrapper<VerifierCircuitTarget> {
//     fn clone(&self) -> Self {
//         Wrapper(VerifierCircuitTarget {
//             constants_sigmas_cap: self.0.constants_sigmas_cap.clone(),
//             circuit_digest: self.0.circuit_digest,
//         })
//     }
// }

impl<const D: usize> RecursiveProofTarget<D> {
    pub fn add_virtual_to<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        circuit_data: &CircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let proof_t = builder.add_virtual_proof_with_pis::<C>(&circuit_data.common);
        // let vd_target = VerifierCircuitTarget {
        //     constants_sigmas_cap: builder
        //         .add_virtual_cap(circuit_data.common.config.fri_config.cap_height),
        // };

        let constants_sigmas_cap = MerkleCapTarget(
            circuit_data
                .verifier_only
                .constants_sigmas_cap
                .0
                .iter()
                .cloned()
                .map(|t| builder.constant_hash(t))
                .collect::<Vec<_>>(),
        );

        let circuit_digest = builder.constant_hash(circuit_data.verifier_only.circuit_digest);
        let vd_target = VerifierCircuitTarget {
            constants_sigmas_cap,
            circuit_digest,
        };

        let wrapped_proof_t = Wrapper(proof_t);
        builder.verify_proof::<C>(&wrapped_proof_t.0, &vd_target, &circuit_data.common);

        let enabled = builder.add_virtual_bool_target_safe();

        RecursiveProofTarget {
            inner: wrapped_proof_t,
            verifier_only_data: vd_target,
            enabled,
        }
    }

    pub fn set_witness<F, C>(
        &self,
        pw: &mut impl Witness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        // verifier_only_data: &VerifierOnlyCircuitData<C, D>,
        enabled: bool,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_proof_with_pis_target(&self.inner, proof);
        pw.set_bool_target(self.enabled, enabled);
    }
}

#[test]
fn test_recursion_simple_signature() {
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

    use crate::zkdsa::circuits::make_simple_signature_circuit;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let private_key = HashOut::rand();
    let message = HashOut::rand();

    let config = CircuitConfig::standard_recursion_config();
    let zkdsa_circuit = make_simple_signature_circuit::<F, C, D>(config);

    let mut pw = PartialWitness::new();
    zkdsa_circuit
        .targets
        .set_witness(&mut pw, private_key, message);

    println!("start proving: sender2_received_signature");
    let start = Instant::now();
    let signature = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // proposal block
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let recursion_target = RecursiveProofTarget::add_virtual_to(&mut builder, &zkdsa_circuit.data);
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

    match circuit_data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}

#[test]
fn test_recursion_default_simple_signature() {
    use std::time::Instant;

    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::zkdsa::circuits::make_simple_signature_circuit;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let zkdsa_circuit = make_simple_signature_circuit::<F, C, D>(config);

    let mut pw = PartialWitness::new();
    zkdsa_circuit
        .targets
        .set_witness(&mut pw, Default::default(), Default::default());

    println!("start proving: sender2_received_signature");
    let start = Instant::now();
    let default_signature = zkdsa_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // proposal block
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let recursion_target = RecursiveProofTarget::add_virtual_to(&mut builder, &zkdsa_circuit.data);
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

    match circuit_data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
