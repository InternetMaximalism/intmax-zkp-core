use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::poseidon::gadgets::poseidon_two_to_one;

use super::{super::account::SecretKey, account::private_key_to_public_key_target};

#[derive(Clone, Debug)]
pub struct SimpleSignatureTarget {
    pub private_key: HashOutTarget,
    pub public_key: HashOutTarget,
    pub message: HashOutTarget,
    pub signature: HashOutTarget,
}

impl SimpleSignatureTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let private_key = builder.add_virtual_hash();
        let message = builder.add_virtual_hash();

        let (signature, public_key) = sign_message_target::<F, H, D>(builder, private_key, message);

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
        private_key: SecretKey<F>,
        message: HashOut<F>,
    ) {
        pw.set_hash_target(self.private_key, private_key);
        pw.set_hash_target(self.message, message);
    }
}

/// Returns `(signature, public_key)`
pub fn sign_message_target<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    private_key: HashOutTarget,
    message: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let public_key = private_key_to_public_key_target::<F, H, D>(builder, private_key);
    let signature = poseidon_two_to_one::<F, H, D>(builder, private_key, message);

    (signature, public_key)
}

#[test]
fn test_verify_simple_signature_by_plonky2() {
    use std::time::Instant;

    use plonky2::{
        field::types::Sample,
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

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let target = SimpleSignatureTarget::add_virtual_to::<F, H, D>(&mut builder);
    builder.register_public_inputs(&target.message.elements);
    builder.register_public_inputs(&target.public_key.elements);
    builder.register_public_inputs(&target.signature.elements);
    let data = builder.build::<C>();

    dbg!(&data.common);

    let private_key = HashOut::<F>::rand();
    let message = HashOut::<F>::rand();

    let mut pw = PartialWitness::new();
    target.set_witness(&mut pw, private_key, message);

    println!("start proving");
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    dbg!(&proof.public_inputs);

    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
