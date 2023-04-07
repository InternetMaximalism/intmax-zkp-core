use std::fmt::Debug;

use super::super::goldilocks_poseidon::GoldilocksHashOut;

type V = GoldilocksHashOut;
type Byte16 = [u8; 16];
type Bytes = Vec<u8>;

pub trait StorageLayout {
    type Position;
    type VectorIndex;
    type MappingKey;
    type MerkleProcessProof;
    type MerkleInclusionProof;
    type Error: 'static + Debug + Sync + Send;

    /// Write a single value from SMT.
    fn write_value(
        &mut self,
        position: Self::Position,
        value: V,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error>;

    /// Fetch a single value from SMT.
    fn read_value(
        &self,
        position: Self::Position,
    ) -> Result<(V, Vec<Self::MerkleInclusionProof>), Self::Error>;

    /// Write a single bytes16 from SMT.
    fn write_bytes16(
        &mut self,
        position: Self::Position,
        value: Byte16,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error> {
        self.write_u128(position, u128::from_le_bytes(value))
    }

    /// Fetch a single bytes16 from SMT.
    fn read_bytes16(
        &self,
        position: Self::Position,
    ) -> Result<(Byte16, Vec<Self::MerkleInclusionProof>), Self::Error> {
        let (value, proof) = self.read_u128(position)?;

        Ok((value.to_le_bytes(), proof))
    }

    /// Write a single uint128 from SMT.
    fn write_u128(
        &mut self,
        position: Self::Position,
        value: u128,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error> {
        self.write_value(position, V::from_u128(value))
    }

    /// Fetch a single uint128 from SMT.
    fn read_u128(
        &self,
        position: Self::Position,
    ) -> Result<(u128, Vec<Self::MerkleInclusionProof>), Self::Error> {
        let (value, proof) = self.read_value(position)?;

        Ok((value.to_u128(), proof))
    }

    /// Fetch a single field element in a vector from SMT.
    fn write_vector_value(
        &mut self,
        position: Self::Position,
        index: Self::VectorIndex,
        value: V,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error>;

    /// Fetch a single field element in a vector from SMT.
    fn read_vector_value(
        &self,
        position: Self::Position,
        index: Self::VectorIndex,
    ) -> Result<(V, Vec<Self::MerkleInclusionProof>), Self::Error>;

    /// Fetch a single field element in a vector from SMT.
    fn push_vector_value(
        &mut self,
        position: Self::Position,
        value: V,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error>;

    /// Fetch a single field element in a mapping from SMT.
    fn write_mapping_value(
        &mut self,
        position: Self::Position,
        key: Self::MappingKey,
        value: V,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error>;

    /// Fetch a single field element in a mapping from SMT.
    fn read_mapping_value(
        &self,
        position: Self::Position,
        key: Self::MappingKey,
    ) -> Result<(V, Vec<Self::MerkleInclusionProof>), Self::Error>;

    /// Fetch bytes from SMT.
    fn write_bytes_data(
        &mut self,
        position: Self::Position,
        value: Bytes,
    ) -> Result<Vec<Self::MerkleProcessProof>, Self::Error>;

    /// Fetch bytes from SMT.
    fn read_bytes_data(
        &self,
        position: Self::Position,
    ) -> Result<(Bytes, Vec<Self::MerkleInclusionProof>), Self::Error>;
}
