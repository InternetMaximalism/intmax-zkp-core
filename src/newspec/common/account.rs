use plonky2::hash::hash_types::{HashOut, RichField};

pub struct Address<F: RichField>(F);

pub struct Account<F: RichField> {
    pub private_key: Vec<F>,
    pub public_key: HashOut<F>,
    pub address: Address<F>,
}


