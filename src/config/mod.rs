#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RollupConstants {
    /// world state tree における user 層の tree の深さ
    pub log_max_n_users: usize,

    /// world state tree における transaction 層の tree の深さ
    pub log_max_n_txs: usize,

    /// world state tree における contract address 層の tree の深さ
    pub log_max_n_contracts: usize,

    /// world state tree における variable index 層の tree の深さ
    pub log_max_n_variables: usize,

    /// diff tree における transaction 層の tree の深さ
    pub log_n_txs: usize,

    /// diff tree における recipient 層の tree の深さ
    pub log_n_recipients: usize,

    /// diff tree における contract address 層の tree の深さ
    pub log_n_contracts: usize,

    /// diff tree における variable index 層の tree の深さ
    pub log_n_variables: usize,

    /// 1 つの block に含める新規 account の数
    pub n_registrations: usize,

    /// 1 つの block に含める purge の数
    pub n_diffs: usize,

    /// 1 つの block に含める merge の数
    pub n_merges: usize,

    /// 1 つの block に含める deposit の数
    pub n_deposits: usize,

    /// 1 つの batch でまとめる block の数
    pub n_blocks: usize,
}
