use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, Sample},
    },
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};

use crate::zkdsa::{account::private_key_to_public_key, circuits::SimpleSignaturePublicInputs};

use super::super::account::SecretKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleSignature<F> {
    pub private_key: SecretKey<F>,
    pub message: Vec<F>, // nullifier
}

impl<F: Field> SimpleSignature<F> {
    pub fn new(private_key_len: usize, message_len: usize) -> Self {
        let message = vec![F::ZERO; message_len];
        let private_key = vec![F::ZERO; private_key_len];

        SimpleSignature {
            private_key,
            message,
        }
    }
}

impl<F: Sample> SimpleSignature<F> {
    pub fn rand(private_key_len: usize, message_len: usize) -> Self {
        let private_key = F::rand_vec(private_key_len);
        let message = F::rand_vec(message_len);

        SimpleSignature {
            private_key,
            message,
        }
    }
}

impl<F: RichField> SimpleSignature<F> {
    pub fn calculate(&self) -> SimpleSignaturePublicInputs<F> {
        // XXX: `self.message` が `[F::ZERO; 4]` のとき, `public_key` と `signature` が一致してしまうが問題ないか.
        let public_key = private_key_to_public_key(&self.private_key);
        let signature = PoseidonHash::hash_no_pad(
            &vec![self.private_key.to_vec(), self.message.to_vec()].concat(),
        );

        SimpleSignaturePublicInputs {
            message: self.message.clone(),
            public_key,
            signature,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimpleSignatureTarget {
    pub private_key: Vec<Target>,
    pub public_key: HashOutTarget,
    pub message: Vec<Target>,
    pub signature: HashOutTarget,
}

impl SimpleSignatureTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        private_key_len: usize,
        message_len: usize,
    ) -> Self {
        let private_key = builder.add_virtual_targets(private_key_len);
        let message = builder.add_virtual_targets(message_len);

        let (signature, public_key) =
            verify_simple_signature::<F, H, D>(builder, private_key.clone(), message.clone());

        Self {
            private_key,
            public_key,
            message,
            signature,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut impl Witness<F>,
        witness: &SimpleSignature<F>,
    ) -> SimpleSignaturePublicInputs<F> {
        assert_eq!(self.private_key.len(), witness.private_key.len());
        for (target, value) in self.private_key.iter().zip(witness.private_key.iter()) {
            pw.set_target(*target, *value);
        }

        assert_eq!(self.message.len(), witness.message.len());
        for (target, value) in self.message.iter().zip(witness.message.iter()) {
            pw.set_target(*target, *value);
        }

        witness.calculate()
    }
}

/// Returns `(signature, public_key)`
pub fn verify_simple_signature<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    private_key: Vec<Target>,
    message: Vec<Target>,
) -> (HashOutTarget, HashOutTarget) {
    let public_key = builder.hash_n_to_hash_no_pad::<H>(private_key.to_vec());
    let signature = builder.hash_n_to_hash_no_pad::<H>(vec![private_key, message].concat());

    (signature, public_key)
}

#[test]
fn test_verify_simple_signature_by_plonky2() {
    use std::time::Instant;

    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    const D: usize = 2; // extension degree
    type C = PoseidonGoldilocksConfig;
    type H = <C as GenericConfig<D>>::InnerHasher;
    type F = <C as GenericConfig<D>>::F;
    // type F = GoldilocksField;

    let private_key_len = 4;
    let message_len = 4;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let target = SimpleSignatureTarget::add_virtual_to::<F, H, D>(
        &mut builder,
        private_key_len,
        message_len,
    );
    builder.register_public_inputs(&target.message);
    builder.register_public_inputs(&target.public_key.elements);
    builder.register_public_inputs(&target.signature.elements);
    let data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    target.set_witness(
        &mut pw,
        &SimpleSignature::rand(private_key_len, message_len),
    );

    println!("start proving");
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    // dbg!(&proof.public_inputs);

    data.verify(proof).unwrap();
}
