use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::GenericConfig,
        proof::{Proof, ProofWithPublicInputs},
    },
};
use serde::{Deserialize, Serialize};

use crate::utils::hash::{SerializableHashOut, WrappedHashOut};

use super::gadgets::signature::{SimpleSignature, SimpleSignatureTarget};

pub fn make_simple_signature_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    private_key_len: usize,
    message_len: usize,
) -> SimpleSignatureCircuit<F, C, D> {
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let targets = SimpleSignatureTarget::add_virtual_to::<F, C::InnerHasher, D>(
        &mut builder,
        private_key_len,
        message_len,
    );
    let public_inputs = SimpleSignaturePublicInputsTarget {
        message: targets.message.clone(),
        public_key: targets.public_key,
        signature: targets.signature,
    };
    builder.register_public_inputs(&public_inputs.encode());
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
#[serde(bound = "F: RichField")]
pub struct SimpleSignaturePublicInputs<F: Field> {
    pub message: Vec<F>, // nullifier
    #[serde(with = "SerializableHashOut")]
    pub public_key: HashOut<F>,
    #[serde(with = "SerializableHashOut")]
    pub signature: HashOut<F>, // nullifier hash
}

impl<F: RichField> SimpleSignaturePublicInputs<F> {
    pub fn new(private_key_len: usize, message_len: usize) -> Self {
        SimpleSignature::new(private_key_len, message_len).calculate()
    }
}

#[test]
fn test_default_simple_signature() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;

    let default_user_transaction = SimpleSignaturePublicInputs::<F>::new(4, 4);

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

    assert_eq!(default_user_transaction.message, vec![F::ZERO; 4]);
    assert_eq!(default_user_transaction.public_key, public_key);
    assert_eq!(default_user_transaction.signature, signature);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct SerializableSimpleSignaturePublicInputs<F: Field> {
    pub message: Vec<F>,
    pub public_key: WrappedHashOut<F>,
    pub signature: WrappedHashOut<F>,
}

impl<F: Field> From<SerializableSimpleSignaturePublicInputs<F>> for SimpleSignaturePublicInputs<F> {
    fn from(value: SerializableSimpleSignaturePublicInputs<F>) -> Self {
        Self {
            message: value.message,
            public_key: value.public_key.0,
            signature: value.signature.0,
        }
    }
}

impl<F: Field> From<SimpleSignaturePublicInputs<F>> for SerializableSimpleSignaturePublicInputs<F> {
    fn from(value: SimpleSignaturePublicInputs<F>) -> Self {
        Self {
            message: value.message,
            public_key: value.public_key.into(),
            signature: value.signature.into(),
        }
    }
}

#[test]
fn test_serde_simple_signature_public_inputs() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;

    let public_inputs: SimpleSignaturePublicInputs<F> = SimpleSignaturePublicInputs::new(4, 4);
    // let encode_public_inputs = serde_json::to_string(&public_inputs).unwrap();
    // dbg!(encode_public_inputs);
    let encoded_public_inputs = "{\"message\":[0,0,0,0],\"public_key\":\"0xc71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359\",\"signature\":\"0xc71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359\"}";
    let decoded_public_inputs: SimpleSignaturePublicInputs<F> =
        serde_json::from_str(encoded_public_inputs).unwrap();
    assert_eq!(decoded_public_inputs, public_inputs);
}

impl<F: Field> SimpleSignaturePublicInputs<F> {
    pub fn encode(&self) -> Vec<F> {
        vec![
            self.public_key.elements.to_vec(),
            self.signature.elements.to_vec(),
            self.message.to_vec(),
        ]
        .concat()
    }

    pub fn decode(public_inputs: &[F], message_len: usize) -> Self {
        assert_eq!(public_inputs.len(), 8 + message_len);
        let public_key = HashOut::from_partial(&public_inputs[0..4]);
        let signature = HashOut::from_partial(&public_inputs[4..8]);
        let message = public_inputs[8..(8 + message_len)].to_vec();

        Self {
            message,
            public_key,
            signature,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimpleSignaturePublicInputsTarget {
    pub message: Vec<Target>,
    pub public_key: HashOutTarget,
    pub signature: HashOutTarget,
}

impl SimpleSignaturePublicInputsTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let message = builder.add_virtual_targets(4);
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
        for (target, value) in self.message.iter().zip(public_inputs.message.iter()) {
            pw.set_target(*target, *value);
        }

        pw.set_hash_target(self.public_key, public_inputs.public_key);
        pw.set_hash_target(self.signature, public_inputs.signature);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) {
        for (a, b) in a.message.iter().zip(b.message.iter()) {
            builder.connect(*a, *b);
        }

        builder.connect_hashes(a.public_key, b.public_key);
        builder.connect_hashes(a.signature, b.signature);
    }

    pub fn encode(&self) -> Vec<Target> {
        vec![
            self.public_key.elements.to_vec(),
            self.signature.elements.to_vec(),
            self.message.to_vec(),
        ]
        .concat()
    }

    pub fn decode(public_inputs_t: &[Target], message_len: usize) -> Self {
        assert_eq!(public_inputs_t.len(), 8 + message_len);
        let public_key = HashOutTarget {
            elements: public_inputs_t[0..4].try_into().unwrap(),
        };
        let signature = HashOutTarget {
            elements: public_inputs_t[4..8].try_into().unwrap(),
        };
        let message = public_inputs_t[8..(8 + message_len)].to_vec();

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
            public_inputs: SimpleSignaturePublicInputs::decode(&value.public_inputs, 4),
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SimpleSignatureCircuit<F, C, D>
{
    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;

        Ok(proof_with_pis.into())
    }

    pub fn set_witness_and_prove(
        &self,
        witness: &SimpleSignature<F>,
    ) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        self.targets.set_witness(&mut pw, witness);
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
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use super::account::private_key_to_account;

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // type F = GoldilocksField;

    let private_key_len = 4;
    let message_len = 4;

    let config = CircuitConfig::standard_recursion_config();
    let simple_signature_circuit =
        make_simple_signature_circuit::<F, C, D>(config, private_key_len, message_len);

    let witness = SimpleSignature::rand(private_key_len, message_len);
    let account = private_key_to_account(witness.private_key.clone());

    let mut pw = PartialWitness::new();
    simple_signature_circuit
        .targets
        .set_witness(&mut pw, &witness);

    println!("start proving");
    let start = Instant::now();
    let proof = simple_signature_circuit.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    assert_eq!(account.public_key, proof.public_inputs.public_key);

    simple_signature_circuit.verify(proof).unwrap();
}

/// witness を入力にとり、 simple_signature を返す関数
pub fn prove_simple_signature<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const LOG_MAX_N_USERS: usize,
    const LOG_MAX_N_TXS: usize,
    const LOG_MAX_N_CONTRACTS: usize,
    const LOG_MAX_N_VARIABLES: usize,
    const LOG_N_TXS: usize,
    const LOG_N_RECIPIENTS: usize,
    const LOG_N_CONTRACTS: usize,
    const LOG_N_VARIABLES: usize,
    const N_DIFFS: usize,
    const N_MERGES: usize,
>(
    witness: &SimpleSignature<F>,
) -> anyhow::Result<SimpleSignatureProofWithPublicInputs<F, C, D>> {
    // let config = CircuitConfig::standard_recursion_zk_config(); // TODO
    let config = CircuitConfig::standard_recursion_config();
    let simple_signature_circuit =
        make_simple_signature_circuit(config, witness.private_key.len(), witness.message.len());

    let mut pw = PartialWitness::new();
    simple_signature_circuit
        .targets
        .set_witness(&mut pw, witness);

    let simple_signature_proof = simple_signature_circuit.prove(pw).unwrap();

    Ok(simple_signature_proof)
}
