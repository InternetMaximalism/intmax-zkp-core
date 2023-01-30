use plonky2::hash::hash_types::{HashOut, RichField};

pub struct UserState<F: RichField> {
    pub asset_root: HashOut<F>,
    pub nullifier_hash_root: HashOut<F>,
    pub public_key: HashOut<F>,
}

impl<F: RichField> UserState<F> {
    pub fn default(&self) -> Self {
        todo!()
    }
    pub fn hash(&self) -> HashOut<F> {
        todo!()
    }
}
