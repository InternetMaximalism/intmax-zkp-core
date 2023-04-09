#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RollupConstants {
    /// The depth of the user layer tree in the world state tree
    pub log_max_n_users: usize,

    /// The depth of the transaction layer tree in the world state tree
    pub log_max_n_txs: usize,

    /// The depth of the contract address layer tree in the world state tree
    pub log_max_n_contracts: usize,

    /// The depth of the variable index layer tree in the world state tree
    pub log_max_n_variables: usize,

    /// The depth of the transaction layer tree in the diff tree
    pub log_n_txs: usize,

    /// The depth of the recipient layer tree in the diff tree
    pub log_n_recipients: usize,

    /// The depth of the contract address layer tree in the diff tree
    pub log_n_contracts: usize,

    /// The depth of the variable index layer tree in the diff tree
    pub log_n_variables: usize,

    /// The number of new accounts included in one block
    pub n_registrations: usize,

    /// The number of purges included in one block
    pub n_diffs: usize,

    /// The number of merges included in one block
    pub n_merges: usize,

    /// The number of deposits included in one block
    pub n_deposits: usize,

    /// The number of scroll flags included in one block
    pub n_scroll_flags: usize,

    /// The number of polygon flags included in one block
    pub n_polygon_flags: usize,

    /// The number of blocks included in one batch
    pub n_blocks: usize,
}
