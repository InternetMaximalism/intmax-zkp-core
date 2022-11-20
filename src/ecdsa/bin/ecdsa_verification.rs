use plonky2::{
    field::{secp256k1_scalar::Secp256K1Scalar, types::Field},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_ecdsa::{
    curve::{
        curve_types::{Curve, CurveScalar},
        ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
    gadgets::{
        curve::CircuitBuilderCurve,
        ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
        nonnative::CircuitBuilderNonNative,
    },
};

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_ecc_config();
    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let msg = Secp256K1Scalar::rand();
    let msg_target = builder.constant_nonnative(msg);

    let sk = ECDSASecretKey(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Secp256K1::GENERATOR_PROJECTIVE).to_affine());

    let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

    let sig = sign_message(msg, sk);

    let is_ok = verify_message(msg, sig, pk);
    assert!(is_ok, "fail to verify ECDSA signature");

    let ECDSASignature { r, s } = sig;
    let r_target = builder.constant_nonnative(r);
    let s_target = builder.constant_nonnative(s);
    let sig_target = ECDSASignatureTarget {
        r: r_target,
        s: s_target,
    };
    verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);
    println!("{sig:?}");
    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();
    match data.verify(proof) {
        Ok(()) => println!("Ok!"),
        Err(x) => println!("{}", x),
    }
}
