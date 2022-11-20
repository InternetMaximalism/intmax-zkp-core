use plonky2::{
    field::extension::Extendable,
    fri::proof::FriProofTarget,
    gadgets::polynomial::PolynomialCoeffsExtTarget,
    hash::hash_types::{HashOutTarget, MerkleCapTarget, RichField},
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

#[derive(Clone, Debug)]
pub struct RecursiveProofTarget<const D: usize> {
    pub inner: Wrapper<ProofWithPublicInputsTarget<D>>,
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

impl Clone for Wrapper<VerifierCircuitTarget> {
    fn clone(&self) -> Self {
        Wrapper(VerifierCircuitTarget {
            constants_sigmas_cap: self.0.constants_sigmas_cap.clone(),
            circuit_digest: self.0.circuit_digest,
        })
    }
}

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

        let vd_target = VerifierCircuitTarget {
            constants_sigmas_cap: MerkleCapTarget(
                circuit_data
                    .verifier_only
                    .constants_sigmas_cap
                    .0
                    .iter()
                    .map(|t| HashOutTarget {
                        elements: [
                            builder.constant(t.elements[0]),
                            builder.constant(t.elements[1]),
                            builder.constant(t.elements[2]),
                            builder.constant(t.elements[3]),
                        ],
                    })
                    .collect::<Vec<_>>(),
            ),
            circuit_digest: builder.add_virtual_hash(),
        };

        let wrapped_proof_t = Wrapper(proof_t);
        builder.verify_proof::<C>(wrapped_proof_t.clone().0, &vd_target, &circuit_data.common); // TODO

        let enabled = builder.add_virtual_bool_target_safe();

        RecursiveProofTarget {
            inner: wrapped_proof_t,
            enabled,
        }
    }

    pub fn set_witness<F, C>(
        &self,
        pw: &mut impl Witness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
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
