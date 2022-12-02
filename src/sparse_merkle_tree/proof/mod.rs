pub mod common;
mod inclusion;
mod process;

pub use self::{
    inclusion::SparseMerkleInclusionProof,
    process::{verify_smt_process_proof, ProcessMerkleProofRole, SparseMerkleProcessProof},
};
