use super::account::Address;
use plonky2::hash::hash_types::{HashOut, RichField};

/// Information about the block to be posted to L1.
/// The block hash depends only on this `BlockHeader`.
pub struct BlockHeader<F: RichField> {
    /// The block number of intmax's L2 block
    pub block_number: F,

    /// previous_block
    pub previous_block: HashOut<F>,

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

    /// The root of deposit tx tree.
    pub deposit_root: HashOut<F>,
}
