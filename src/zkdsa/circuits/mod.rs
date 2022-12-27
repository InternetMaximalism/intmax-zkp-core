use plonky2::{
    field::{extension::Extendable, types::Field},
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
        config::{GenericConfig, Hasher},
        proof::{Proof, ProofWithPublicInputs},
    },
};
use serde::{Deserialize, Serialize};

use crate::sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut;

use super::{account::SecretKey, gadgets::signature::SimpleSignatureTarget};

pub fn make_simple_signature_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
) -> SimpleSignatureCircuit<F, C, D> {
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let targets = SimpleSignatureTarget::add_virtual_to::<F, C::InnerHasher, D>(&mut builder);
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

impl<F: RichField> Default for SimpleSignaturePublicInputs<F> {
    fn default() -> Self {
        let message = Default::default();
        let private_key = Default::default();
        let public_key = PoseidonHash::two_to_one(private_key, private_key);
        let signature = PoseidonHash::two_to_one(private_key, message);

        Self {
            message,
            public_key,
            signature,
        }
    }
}

#[test]
fn test_default_simple_signature() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;

    let default_user_transaction = SimpleSignaturePublicInputs::<F>::default();

    let public_key = HashOut {
        elements: [
            F::from_canonical_u64(4330397376401421145),
            F::from_canonical_u64(14124799381142128323),
            F::from_canonical_u64(8742572140681234676),
            F::from_canonical_u64(14345658006221440202),
        ],
    };

    let signature = HashOut {
        elements: [
            F::from_canonical_u64(4330397376401421145),
            F::from_canonical_u64(14124799381142128323),
            F::from_canonical_u64(8742572140681234676),
            F::from_canonical_u64(14345658006221440202),
        ],
    };

    assert_eq!(default_user_transaction.message, Default::default());
    assert_eq!(default_user_transaction.public_key, public_key);
    assert_eq!(default_user_transaction.signature, signature);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct SerializableSimpleSignaturePublicInputs<F: Field> {
    pub message: WrappedHashOut<F>,
    pub public_key: WrappedHashOut<F>,
    pub signature: WrappedHashOut<F>,
}

impl<F: Field> From<SerializableSimpleSignaturePublicInputs<F>> for SimpleSignaturePublicInputs<F> {
    fn from(value: SerializableSimpleSignaturePublicInputs<F>) -> Self {
        Self {
            message: value.message.0,
            public_key: value.public_key.0,
            signature: value.signature.0,
        }
    }
}

impl<F: Field> From<SimpleSignaturePublicInputs<F>> for SerializableSimpleSignaturePublicInputs<F> {
    fn from(value: SimpleSignaturePublicInputs<F>) -> Self {
        Self {
            message: value.message.into(),
            public_key: value.public_key.into(),
            signature: value.signature.into(),
        }
    }
}

#[test]
fn test_serde_simple_signature_public_inputs() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;

    let public_inputs: SimpleSignaturePublicInputs<F> = SimpleSignaturePublicInputs::default();
    let encoded_public_inputs = "{\"message\":{\"elements\":[0,0,0,0]},\"public_key\":{\"elements\":[4330397376401421145,14124799381142128323,8742572140681234676,14345658006221440202]},\"signature\":{\"elements\":[4330397376401421145,14124799381142128323,8742572140681234676,14345658006221440202]}}";
    let decoded_public_inputs: SimpleSignaturePublicInputs<F> =
        serde_json::from_str(encoded_public_inputs).unwrap();
    assert_eq!(decoded_public_inputs, public_inputs);
}

impl<F: Field> SimpleSignaturePublicInputs<F> {
    pub fn encode(&self) -> Vec<F> {
        let public_inputs = vec![
            self.message.elements,
            self.public_key.elements,
            self.signature.elements,
        ]
        .concat();
        assert_eq!(public_inputs.len(), 12);

        public_inputs
    }

    pub fn decode(public_inputs: &[F]) -> Self {
        assert_eq!(public_inputs.len(), 12);
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

impl SimpleSignaturePublicInputsTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let message = builder.add_virtual_hash();
        let public_key = builder.add_virtual_hash();
        let signature = builder.add_virtual_hash();

        Self {
            message,
            public_key,
            signature,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        public_inputs: &SimpleSignaturePublicInputs<F>,
    ) {
        pw.set_hash_target(self.message, public_inputs.message);
        pw.set_hash_target(self.public_key, public_inputs.public_key);
        pw.set_hash_target(self.signature, public_inputs.signature);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) {
        builder.connect_hashes(a.message, b.message);
        builder.connect_hashes(a.public_key, b.public_key);
        builder.connect_hashes(a.signature, b.signature);
    }

    pub fn encode(&self) -> Vec<Target> {
        let public_inputs_t = vec![
            self.message.elements,
            self.public_key.elements,
            self.signature.elements,
        ]
        .concat();
        assert_eq!(public_inputs_t.len(), 12);

        public_inputs_t
    }

    pub fn decode(public_inputs_t: &[Target]) -> Self {
        assert_eq!(public_inputs_t.len(), 12);
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

// pub fn parse_simple_signature_public_inputs(
//     public_inputs_t: &[Target],
// ) -> SimpleSignaturePublicInputsTarget {
//     let message = HashOutTarget {
//         elements: public_inputs_t[0..4].try_into().unwrap(),
//     };
//     let public_key = HashOutTarget {
//         elements: public_inputs_t[4..8].try_into().unwrap(),
//     };
//     let signature = HashOutTarget {
//         elements: public_inputs_t[8..12].try_into().unwrap(),
//     };

//     SimpleSignaturePublicInputsTarget {
//         message,
//         public_key,
//         signature,
//     }
// }

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SimpleSignatureCircuit<F, C, D>
{
    pub fn parse_public_inputs(&self) -> SimpleSignaturePublicInputsTarget {
        let public_inputs_t = self.data.prover_only.public_inputs.clone();

        SimpleSignaturePublicInputsTarget::decode(&public_inputs_t)
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;

        Ok(proof_with_pis.into())
    }

    pub fn set_witness_and_prove(
        &self,
        private_key: SecretKey<F>,
        message: HashOut<F>,
    ) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        self.targets.set_witness(&mut pw, private_key, message);
        self.prove(pw)
    }

    pub fn verify(
        &self,
        proof_with_pis: SimpleSignatureProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.data
            .verify(ProofWithPublicInputs::from(proof_with_pis))
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

    let config = CircuitConfig::standard_recursion_config();
    let simple_signature_circuit = make_simple_signature_circuit::<F, C, D>(config);

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

    assert_eq!(account.public_key, proof.public_inputs.public_key);

    match simple_signature_circuit.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}

/// witness を入力にとり、 simple_signature を返す関数
pub fn prove_simple_signature<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
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
    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let simple_signature_circuit = make_simple_signature_circuit(config);

    let mut pw = PartialWitness::new();
    simple_signature_circuit
        .targets
        .set_witness(&mut pw, *private_key, *message);

    let simple_signature_proof = simple_signature_circuit.prove(pw).unwrap();

    Ok(simple_signature_proof)
}
