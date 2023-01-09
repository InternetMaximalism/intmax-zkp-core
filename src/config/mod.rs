#[derive(Clone, PartialEq, Eq)]
pub struct RollupConfig {
    pub log_max_n_users: usize,
    pub log_max_n_txs: usize,
    pub log_max_n_contracts: usize,
    pub log_max_n_variables: usize,
    pub log_n_txs: usize,
    pub log_n_recipients: usize,
    pub log_n_contracts: usize,
    pub log_n_variables: usize,
    pub n_diffs: usize,
    pub n_merges: usize,
    pub n_txs: usize,
    pub n_deposits: usize,
}
