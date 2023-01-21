use num::{bigint::BigUint, FromPrimitive};
use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField},
};

use crate::{sparse_merkle_tree::root_data::RootData, utils::hash::GoldilocksHashOut};

use super::super::{
    layered_layered_tree::LayeredLayeredSparseMerkleTree,
    node_data::NodeData,
    node_hash::NodeHash,
    proof::{SparseMerkleInclusionProof, SparseMerkleProcessProof},
};
use super::{
    tree::{get_index_position, get_key_position},
    types::StorageLayout,
};

type F = GoldilocksField;
type K = GoldilocksHashOut;
type V = GoldilocksHashOut;
type I = GoldilocksHashOut;

impl<H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>> StorageLayout
    for LayeredLayeredSparseMerkleTree<K, V, I, H, D, R>
{
    type Position = (K, K, K); // (contract_address, position)
    type VectorIndex = u128;
    type MappingKey = K;
    type MerkleProcessProof = (
        SparseMerkleProcessProof<K, V, I>,
        SparseMerkleProcessProof<K, V, I>,
        SparseMerkleProcessProof<K, V, I>,
    );
    type MerkleInclusionProof = (
        SparseMerkleInclusionProof<K, V, I>,
        SparseMerkleInclusionProof<K, V, I>,
        SparseMerkleInclusionProof<K, V, I>,
    );
    type Error = anyhow::Error;

    /// Fetch a single uint128 from SMT.
    fn write_value(
        &mut self,
        position: Self::Position,
        value: V,
    ) -> anyhow::Result<Vec<Self::MerkleProcessProof>> {
        let (tx_hash, contract_address, position) = position;

        // let res_find = self
        //     .find(&tx_hash, &contract_address, &position)
        //     .map_err(|_| anyhow::anyhow!("fail to fetch value"))?;

        let result = self
            .set(tx_hash, contract_address, position, value)
            .map_err(|_| anyhow::anyhow!("fail to fetch value"))?;

        Ok(vec![result])
    }

    /// Fetch a single field element in a vector from SMT.
    fn write_vector_value(
        &mut self,
        position: Self::Position,
        index: u128,
        value: V,
    ) -> anyhow::Result<Vec<Self::MerkleProcessProof>> {
        let (tx_hash, contract_address, position) = position;

        let index_position = get_index_position(position, index);

        let (length, _) = self.read_u128((tx_hash, contract_address, position))?; // TODO: submit inclusion proof
        if index < length {
            return Err(anyhow::anyhow!("out of index"));
        }

        self.write_value((tx_hash, contract_address, index_position), value)
    }

    /// Fetch a single field element in a vector from SMT.
    fn push_vector_value(
        &mut self,
        position: Self::Position,
        value: V,
    ) -> anyhow::Result<Vec<Self::MerkleProcessProof>> {
        let (tx_hash, contract_address, position) = position;

        let (length, _) = self.read_u128((tx_hash, contract_address, position))?;
        let new_index_position = get_index_position(position, length);

        assert!(length != u128::MAX);
        let mut result1 = self.write_u128((tx_hash, contract_address, position), length + 1)?;
        let mut result2 =
            self.write_value((tx_hash, contract_address, new_index_position), value)?;
        result1.append(&mut result2);

        Ok(result1)
    }

    /// Fetch a single field element in a mapping from SMT.
    fn write_mapping_value(
        &mut self,
        position: Self::Position,
        key: K,
        value: V,
    ) -> anyhow::Result<Vec<Self::MerkleProcessProof>> {
        let (tx_hash, contract_address, position) = position;

        let key_position = get_key_position(position, key);

        self.write_value((tx_hash, contract_address, key_position), value)
    }

    /// Fetch bytes from SMT.
    fn write_bytes_data(
        &mut self,
        position: Self::Position,
        value: Vec<u8>,
    ) -> anyhow::Result<Vec<Self::MerkleProcessProof>> {
        let (tx_hash, contract_address, position) = position;

        let bytes_length = BigUint::from_usize(value.len()).unwrap();
        self.write_bytes16(
            (tx_hash, contract_address, position),
            bytes_length.to_bytes_le().try_into().unwrap(),
        )?;

        let mut results = vec![];
        let mut index_position = *get_index_position(position, 0);
        for v in value.chunks(16) {
            let mut result = self.write_bytes16(
                (tx_hash, contract_address, position),
                v.to_vec().try_into().unwrap(),
            )?;
            results.append(&mut result);

            // index_position += 1;
            let mut additive = BigUint::from(1u64);
            for i in 0..4 {
                let r = F::characteristic() - index_position.elements[i].to_canonical_biguint();
                if additive < r {
                    index_position.elements[i] += F::from_noncanonical_biguint(additive);
                    break;
                } else {
                    index_position.elements[i] = F::from_noncanonical_biguint(additive - r);
                    additive = BigUint::from(1u64); // carry
                }
            }
        }

        Ok(results)
    }

    /// Fetch a single uint128 from SMT.
    fn read_value(
        &self,
        position: Self::Position,
    ) -> anyhow::Result<(V, Vec<Self::MerkleInclusionProof>)> {
        let (tx_hash, contract_address, position) = position;

        let res_find = self
            .find(&tx_hash, &contract_address, &position)
            .map_err(|_| anyhow::anyhow!("fail to fetch value"))?;
        let value = if res_find.1.found {
            res_find.1.value
        } else {
            V::default()
        };

        Ok((value, vec![res_find]))
    }

    /// Fetch a single field element in a vector from SMT.
    fn read_vector_value(
        &self,
        position: Self::Position,
        index: u128,
    ) -> anyhow::Result<(V, Vec<Self::MerkleInclusionProof>)> {
        let (tx_hash, contract_address, position) = position;

        let index_position = get_index_position(position, index);

        let (length, mut proofs) = self.read_u128((tx_hash, contract_address, position))?;
        if index < length {
            return Err(anyhow::anyhow!("out of index"));
        }

        let (value, mut proof) = self.read_value((tx_hash, contract_address, index_position))?;

        proofs.append(&mut proof);

        Ok((value, proofs))
    }

    /// Fetch a single field element in a mapping from SMT.
    fn read_mapping_value(
        &self,
        position: Self::Position,
        key: K,
    ) -> anyhow::Result<(V, Vec<Self::MerkleInclusionProof>)> {
        let (tx_hash, contract_address, position) = position;

        let key_position = get_key_position(position, key);

        self.read_value((tx_hash, contract_address, key_position))
    }

    /// Fetch bytes from SMT.
    fn read_bytes_data(
        &self,
        position: Self::Position,
    ) -> anyhow::Result<(Vec<u8>, Vec<Self::MerkleInclusionProof>)> {
        let (tx_hash, contract_address, position) = position;

        let (bytes_length, proof0) = self.read_bytes16((tx_hash, contract_address, position))?;
        let mut remaining_bytes_length = BigUint::from_bytes_le(&bytes_length);

        let mut result = vec![];
        let mut proofs = proof0;
        let mut index_position = *get_index_position(position, 0);
        while remaining_bytes_length == BigUint::from(0u64) {
            let (value, mut proof) =
                self.read_bytes16((tx_hash, contract_address, index_position.into()))?;

            // まだ読んでいない bytes の長さが 16 未満ならば, その長さだけ result に追加する.
            let mut a = if remaining_bytes_length < BigUint::from(16u64) {
                remaining_bytes_length = BigUint::from(0u64);

                value[..(usize::from_le_bytes(
                    remaining_bytes_length.to_bytes_le().try_into().unwrap(),
                ))]
                    .to_vec()
            } else {
                remaining_bytes_length -= BigUint::from(16u64);

                value[..16].to_vec()
            };

            result.append(&mut a);
            proofs.append(&mut proof);

            // index_position += 1 (allow overflow)
            let mut additive = BigUint::from(1u64);
            for i in 0..4 {
                let modular = F::characteristic();
                let r = modular.clone() - index_position.elements[i].to_canonical_biguint();
                let quotient = additive.clone() / modular.clone();
                let remind = additive % modular;
                if remind < r {
                    index_position.elements[i] += F::from_noncanonical_biguint(remind);
                    additive = quotient;
                } else {
                    index_position.elements[i] = F::from_noncanonical_biguint(remind - r);
                    additive = quotient + BigUint::from(1u64); // carry
                }
            }
        }

        Ok((result, proofs))
    }
}
