use plonky2::{
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};

use super::account::{private_key_to_public_key, PublicKey, SecretKey};

/// Returns `(signature, public_key)`
pub fn sign_message<F: RichField>(
    private_key: SecretKey<F>,
    message: HashOut<F>,
) -> (HashOut<F>, PublicKey<F>) {
    let public_key = private_key_to_public_key(private_key);
    let signature = PoseidonHash::two_to_one(private_key, message);

    (signature, public_key)
}
