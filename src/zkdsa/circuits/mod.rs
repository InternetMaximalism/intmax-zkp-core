use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::{Proof, ProofWithPublicInputs},
    },
};
use serde::{Deserialize, Serialize};

use crate::sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut;

use super::gadgets::signature::SimpleSignatureTarget;

type C = PoseidonGoldilocksConfig;
type H = <C as GenericConfig<D>>::InnerHasher;
type F = <C as GenericConfig<D>>::F;
const D: usize = 2;

pub fn make_simple_signature_circuit() -> SimpleSignatureCircuit<F, C, D> {
    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let targets = SimpleSignatureTarget::add_virtual_to::<F, H, D>(&mut builder);
    builder.register_public_inputs(&targets.message.elements); // public_inputs[0..4]
    builder.register_public_inputs(&targets.public_key.elements); // public_inputs[4..8]
    builder.register_public_inputs(&targets.signature.elements); // public_inputs[8..12]
    let zkdsa_circuit_data = builder.build::<C>();

    SimpleSignatureCircuit {
        data: zkdsa_circuit_data,
        targets,
    }
}

pub struct SimpleSignatureCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub data: CircuitData<F, C, D>,
    pub targets: SimpleSignatureTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SimpleSignaturePublicInputs<F: Field> {
    pub message: HashOut<F>,
    pub public_key: HashOut<F>,
    pub signature: HashOut<F>,
}

impl<F: Field> SimpleSignaturePublicInputs<F> {
    pub fn encode(&self) -> Vec<F> {
        let mut public_inputs = vec![];
        public_inputs.append(&mut self.message.elements.into());
        public_inputs.append(&mut self.public_key.elements.into());
        public_inputs.append(&mut self.signature.elements.into());

        public_inputs
    }

    pub fn decode(public_inputs: &[F]) -> Self {
        let message = HashOut::from_partial(&public_inputs[0..4]);
        let public_key = HashOut::from_partial(&public_inputs[4..8]);
        let signature = HashOut::from_partial(&public_inputs[8..12]);

        Self {
            message,
            public_key,
            signature,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimpleSignaturePublicInputsTarget {
    pub message: HashOutTarget,
    pub public_key: HashOutTarget,
    pub signature: HashOutTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SimpleSignatureProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: Proof<F, C, D>,
    pub public_inputs: SimpleSignaturePublicInputs<F>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    From<SimpleSignatureProofWithPublicInputs<F, C, D>> for ProofWithPublicInputs<F, C, D>
{
    fn from(
        value: SimpleSignatureProofWithPublicInputs<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        Self {
            proof: value.proof,
            public_inputs: value.public_inputs.encode(),
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    From<ProofWithPublicInputs<F, C, D>> for SimpleSignatureProofWithPublicInputs<F, C, D>
{
    fn from(
        value: ProofWithPublicInputs<F, C, D>,
    ) -> SimpleSignatureProofWithPublicInputs<F, C, D> {
        Self {
            proof: value.proof,
            public_inputs: SimpleSignaturePublicInputs::decode(&value.public_inputs),
        }
    }
}

pub fn parse_simple_signature_public_inputs(
    public_inputs_t: &[Target],
) -> SimpleSignaturePublicInputsTarget {
    let message = HashOutTarget {
        elements: public_inputs_t[0..4].try_into().unwrap(),
    };
    let public_key = HashOutTarget {
        elements: public_inputs_t[4..8].try_into().unwrap(),
    };
    let signature = HashOutTarget {
        elements: public_inputs_t[8..12].try_into().unwrap(),
    };

    SimpleSignaturePublicInputsTarget {
        message,
        public_key,
        signature,
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SimpleSignatureCircuit<F, C, D>
{
    pub fn parse_public_inputs(&self) -> SimpleSignaturePublicInputsTarget {
        let public_inputs_t = self.data.prover_only.public_inputs.clone();

        parse_simple_signature_public_inputs(&public_inputs_t)
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;

        Ok(proof_with_pis.into())
    }

    pub fn verify(
        &self,
        proof_with_pis: SimpleSignatureProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        let public_inputs = proof_with_pis.public_inputs.encode();

        self.data.verify(ProofWithPublicInputs {
            proof: proof_with_pis.proof,
            public_inputs,
        })
    }
}

#[test]
fn test_verify_simple_signature_by_plonky2() {
    use std::time::Instant;

    use plonky2::{
        field::types::Sample,
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use super::account::private_key_to_account;

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // type F = GoldilocksField;

    let simple_signature_circuit = make_simple_signature_circuit();

    let private_key = HashOut::<F>::rand();
    let account = private_key_to_account(private_key);
    let message = HashOut::<F>::rand();

    let mut pw = PartialWitness::new();
    simple_signature_circuit
        .targets
        .set_witness(&mut pw, private_key, message);

    println!("start proving");
    let start = Instant::now();
    let proof = simple_signature_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    dbg!(&proof.public_inputs, account);

    assert_eq!(account.public_key, proof.public_inputs.public_key);

    match simple_signature_circuit.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}

/// witness を入力にとり、 simple_signature を返す関数
pub fn prove_simple_signature<
    const N_LOG_MAX_USERS: usize,
    const N_LOG_MAX_TXS: usize,
    const N_LOG_MAX_CONTRACTS: usize,
    const N_LOG_MAX_VARIABLES: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_DIFFS: usize,
    const N_MERGES: usize,
>(
    private_key: WrappedHashOut<F>,
    message: WrappedHashOut<F>,
) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
    let simple_signature_circuit = make_simple_signature_circuit();

    let mut pw = PartialWitness::new();
    simple_signature_circuit
        .targets
        .set_witness(&mut pw, *private_key, *message);

    let simple_signature_proof = simple_signature_circuit.prove(pw).unwrap();

    Ok(simple_signature_proof)
}
