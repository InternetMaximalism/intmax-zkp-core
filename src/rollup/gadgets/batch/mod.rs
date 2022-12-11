use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::recursion::gadgets::RecursiveProofTarget;

#[derive(Clone)]
pub struct BlockBatchTarget<const D: usize, const N_BLOCKS: usize> {
    pub block_proofs: [RecursiveProofTarget<D>; N_BLOCKS],
}

impl<const D: usize, const N_BLOCKS: usize> BlockBatchTarget<D, N_BLOCKS> {
    pub fn add_virtual_to<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        builder: &mut CircuitBuilder<F, D>,
        block_circuit_data: &CircuitData<F, C, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut block_proofs = vec![];

        for _ in 0..N_BLOCKS {
            let target: RecursiveProofTarget<D> =
                RecursiveProofTarget::add_virtual_to::<F, C>(builder, block_circuit_data);
            block_proofs.push(target);
        }

        Self {
            block_proofs: block_proofs
                .try_into()
                .map_err(|_| anyhow::anyhow!("fail to convert vector to constant size array"))
                .unwrap(),
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        block_proofs: &[ProofWithPublicInputs<F, C, D>],
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        assert!(!block_proofs.is_empty());
        assert!(block_proofs.len() <= self.block_proofs.len());
        for (ht, value) in self.block_proofs.iter().zip(block_proofs.iter()) {
            ht.set_witness(pw, value, true);
        }

        for ht in self.block_proofs.iter().skip(block_proofs.len()) {
            ht.set_witness(pw, block_proofs.last().unwrap(), false);
        }
    }
}
