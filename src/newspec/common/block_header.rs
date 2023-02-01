use super::{account::Address, transaction::WithdrawTransaction};
use plonky2::{
    hash::hash_types::{HashOut, RichField},
    iop::target::Target,
};

/// Information about the block to be posted to L1.
/// The block hash depends only on this `BlockHeader`.
pub struct BlockHeader<F: RichField> {
    /// The block number of intmax's L2 block
    pub block_number: F,

    pub previous_block_hash: HashOut<F>,

    /// Current `world_state_root`
    pub world_state_root: HashOut<F>,

    /// The root of the Merkle tree consists of tx senders' user state roots
    /// supposed that all transactions were accepted.
    /// Tx senders sign this value to show their agreements that they recieved the Merkle path
    /// from their user state to this root. The Merkle path will be used in the exit.
    pub partial_world_state_root: HashOut<F>,

    /// The root of the Merkle tree whose key is user's address
    /// and whose value is the last `block_number` when his transaction was accepted.
    /// This tree can be reconstructed by `tx_senders`.
    pub last_activity_root: HashOut<F>,

    /// The address list of tx senders that their tx were accepted
    /// (they responded correct signature).
    pub tx_senders: Vec<Address<F>>,

    /// The root of the Merkle tree that consists of block_hashes.
    pub block_hash_root: HashOut<F>,

    /// The root of tx tree.
    pub tx_root: HashOut<F>,

    /// The root of deposit tx tree from L1.
    pub deposit_root: UINT256,

    pub withdraw_tx: Vec<WithdrawTransaction>,
}

/// Store 32bit per one field.
pub type UINT256 = [u32; 8];
pub type UINT256Target = [Target; 8];

/// Solidity version of BlockHeader which is posted to L1 Verifier contract.
pub struct SolidityBlockHeader {
    pub block_number: UINT256,
    pub previous_block: UINT256,
    pub world_state_root: UINT256,
    pub partial_world_state_root: UINT256,
    pub last_activity_root: UINT256,
    pub tx_senders: Vec<UINT256>,
    pub block_hash_root: UINT256,
    pub tx_root: UINT256,
    pub deposit_root: UINT256,
}

impl SolidityBlockHeader {
    // This hash logic should be verifiable on Solidity
    pub fn solidity_hash(&self) -> UINT256 {
        todo!()
    }
}

impl<F: RichField> BlockHeader<F> {
    pub fn hash(&self) -> UINT256 {
        self.to_solidity_block_header().solidity_hash()
    }
    pub fn to_solidity_block_header(&self) -> SolidityBlockHeader {
        todo!()
    }
}

pub struct SolidityBlockHeaderTarget {
    pub block_number: UINT256Target,
    pub previous_block: UINT256Target,
    pub world_state_root: UINT256Target,
    pub partial_world_state_root: UINT256Target,
    pub last_activity_root: UINT256Target,
    pub tx_senders: Vec<UINT256Target>,
    pub block_hash_root: UINT256Target,
    pub tx_root: UINT256Target,
    pub deposit_root: UINT256Target,
}
