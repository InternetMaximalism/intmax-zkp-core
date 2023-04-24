use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{BytesHash, HashOut, RichField},
        keccak::KeccakHash,
        poseidon::PoseidonHash,
    },
    plonk::config::{GenericHashOut, Hasher},
    util::log2_ceil,
};
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::tree::get_merkle_proof_with_zero,
    rollup::{address_list::TransactionSenderWithValidity, gadgets::deposit_block::DepositInfo},
    sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut,
    transaction::{block_header::BlockHeader, circuits::MergeAndPurgeTransitionPublicInputs},
};

use super::deposit::make_deposit_proof;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo<F: RichField> {
    #[serde(bound(
        serialize = "BlockHeader<F>: Serialize",
        deserialize = "BlockHeader<F>: Deserialize<'de>"
    ))]
    pub header: BlockHeader<F>,
    #[serde(bound(
        serialize = "WrappedHashOut<F>: Serialize",
        deserialize = "WrappedHashOut<F>: Deserialize<'de>"
    ))]
    pub transactions: Vec<WrappedHashOut<F>>,
    #[serde(bound(
        serialize = "DepositInfo<F>: Serialize",
        deserialize = "DepositInfo<F>: Deserialize<'de>"
    ))]
    pub deposit_list: Vec<DepositInfo<F>>,
    #[serde(bound(
        serialize = "DepositInfo<F>: Serialize",
        deserialize = "DepositInfo<F>: Deserialize<'de>"
    ))]
    pub scroll_flag_list: Vec<DepositInfo<F>>,
    #[serde(bound(
        serialize = "DepositInfo<F>: Serialize",
        deserialize = "DepositInfo<F>: Deserialize<'de>"
    ))]
    pub polygon_flag_list: Vec<DepositInfo<F>>,
    #[serde(bound(
        serialize = "TransactionSenderWithValidity<F>: Serialize",
        deserialize = "TransactionSenderWithValidity<F>: Deserialize<'de>"
    ))]
    pub address_list: Vec<TransactionSenderWithValidity<F>>,
    // diff_tree_proof
    // world_state_tree_proof
}

impl<F: RichField> BlockInfo<F> {
    pub fn new(log_num_txs_in_block: usize) -> Self {
        Self {
            header: BlockHeader::new(log_num_txs_in_block),
            transactions: Default::default(),
            deposit_list: Default::default(),
            scroll_flag_list: Default::default(),
            polygon_flag_list: Default::default(),
            address_list: Default::default(),
        }
    }
}

impl BlockInfo<GoldilocksField> {
    pub fn check(&self, log_n_txs: usize) -> anyhow::Result<()> {
        let n_txs = 2usize.pow(log_n_txs as u32);
        let log_n_txs = log2_ceil(n_txs);
        let deposit_proofs = make_deposit_proof(
            &self.deposit_list,
            &self.scroll_flag_list,
            &self.polygon_flag_list,
            Default::default(), // unused
            log_n_txs,
        );
        if *deposit_proofs[0].0.root != self.header.deposit_digest {
            anyhow::bail!("invalid deposit digest");
        }

        let default_tx_hash = MergeAndPurgeTransitionPublicInputs::default().tx_hash;
        if self.transactions.len() > n_txs {
            anyhow::bail!("too many transactions in a block");
        }
        let transactions_digest =
            get_merkle_proof_with_zero(&self.transactions, 0, log_n_txs, default_tx_hash).root;
        if *transactions_digest != self.header.transactions_digest {
            anyhow::bail!("invalid deposit digest");
        }

        Ok(())
    }

    pub fn calc_block_header_keccak(&self, log_n_txs: usize) -> BlockHeaderKeccak {
        let default_tx_hash = to_bytes_hash(*MergeAndPurgeTransitionPublicInputs::default().tx_hash);
        // let default_diff_root = BytesHash([0u8; 32]);
        // let default_nonce = BytesHash([0u8; 32]);
        // let default_tx_hash = <KeccakHash<32> as Hasher<GoldilocksField>>::two_to_one(
        //     default_diff_root,
        //     default_nonce,
        // );

        let transaction_hashes = self
            .transactions
            .iter()
            .map(|v| to_bytes_hash(**v))
            .collect::<Vec<_>>();
        let transactions_digest = calc_merkle_root_with_hasher::<GoldilocksField, KeccakHash<32>>(
            &transaction_hashes,
            0,
            log_n_txs,
            default_tx_hash,
        );

        BlockHeaderKeccak {
            block_number: self.header.block_number,
            prev_block_hash: to_bytes_hash(self.header.prev_block_hash),
            block_headers_digest: to_bytes_hash(self.header.block_headers_digest),
            transactions_digest,
            deposit_digest: to_bytes_hash(self.header.deposit_digest),
            proposed_world_state_digest: to_bytes_hash(self.header.proposed_world_state_digest),
            approved_world_state_digest: to_bytes_hash(self.header.approved_world_state_digest),
            latest_account_digest: to_bytes_hash(self.header.latest_account_digest),
        }
    }
}

fn to_bytes_hash(hash_out: HashOut<GoldilocksField>) -> BytesHash<32> {
    let mut bytes = hash_out.to_bytes();
    bytes.reverse();

    BytesHash(bytes.try_into().unwrap())
}

pub fn calc_merkle_root_with_hasher<F: RichField, H: Hasher<F>>(
    leaves: &[H::Hash],
    index: usize,
    depth: usize,
    zero: H::Hash,
) -> H::Hash {
    let mut nodes = if leaves.is_empty() {
        vec![zero]
    } else {
        leaves.to_vec()
    };
    assert!(index < nodes.len());
    assert!(nodes.len() <= 1usize << depth);
    let num_leaves = nodes.len().next_power_of_two();
    let log_num_leaves = log2_ceil(num_leaves) as usize;
    // let value = nodes[index];
    nodes.resize(num_leaves, zero);

    let mut siblings = vec![zero]; // initialize by zero hashes
    for _ in 1..depth {
        let last_zero = *siblings.last().unwrap();
        siblings.push(H::two_to_one(last_zero, last_zero).into());
    }

    let mut rest_index = index;
    for sibling in siblings.iter_mut().take(log_num_leaves) {
        let _ = std::mem::replace(sibling, nodes[rest_index ^ 1]); // XXX: occur out of index

        let mut new_nodes = vec![];
        for j in 0..(nodes.len() / 2) {
            new_nodes.push(H::two_to_one(nodes[2 * j], nodes[2 * j + 1]).into());
        }

        rest_index >>= 1;
        nodes = new_nodes;
    }

    assert_eq!(nodes.len(), 1);
    let mut root = nodes[0];
    for sibling in siblings.iter().cloned().skip(log_num_leaves) {
        // Above the log_num_leaves layer, sibling is always on the right.
        root = H::two_to_one(root, sibling).into();
    }

    root
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeaderWithHasher<F: RichField, H: Hasher<F>> {
    pub block_number: u32,
    pub prev_block_hash: H::Hash,      // not keccak version
    pub block_headers_digest: H::Hash, // block header tree root
    pub transactions_digest: H::Hash,  // state diff tree root
    pub deposit_digest: H::Hash,       // deposit tree root (include scroll root)
    pub proposed_world_state_digest: H::Hash,
    pub approved_world_state_digest: H::Hash,
    pub latest_account_digest: H::Hash, // latest account tree
}

impl<F: RichField> From<BlockHeader<F>> for BlockHeaderWithHasher<F, PoseidonHash> {
    fn from(value: BlockHeader<F>) -> Self {
        Self {
            block_number: value.block_number,
            prev_block_hash: value.prev_block_hash,
            block_headers_digest: value.block_headers_digest,
            transactions_digest: value.transactions_digest,
            deposit_digest: value.deposit_digest,
            proposed_world_state_digest: value.proposed_world_state_digest,
            approved_world_state_digest: value.approved_world_state_digest,
            latest_account_digest: value.latest_account_digest,
        }
    }
}

impl<F: RichField> From<BlockHeaderWithHasher<F, PoseidonHash>> for BlockHeader<F> {
    fn from(value: BlockHeaderWithHasher<F, PoseidonHash>) -> Self {
        Self {
            block_number: value.block_number,
            prev_block_hash: value.prev_block_hash,
            block_headers_digest: value.block_headers_digest,
            transactions_digest: value.transactions_digest,
            deposit_digest: value.deposit_digest,
            proposed_world_state_digest: value.proposed_world_state_digest,
            approved_world_state_digest: value.approved_world_state_digest,
            latest_account_digest: value.latest_account_digest,
        }
    }
}

pub type BlockHeaderPoseidon = BlockHeaderWithHasher<GoldilocksField, PoseidonHash>;
pub type BlockHeaderKeccak = BlockHeaderWithHasher<GoldilocksField, KeccakHash<32>>;

impl<F: RichField, H: Hasher<F>> BlockHeaderWithHasher<F, H> {
    pub fn block_hash(&self) -> H::Hash {
        let mut block_number = self.block_number.to_le_bytes().to_vec();
        block_number.resize(32, 0);

        let block_number = <H::Hash as GenericHashOut<F>>::from_bytes(&block_number);

        let a = H::two_to_one(block_number, self.latest_account_digest);
        let b = H::two_to_one(self.deposit_digest, self.transactions_digest);
        let c = H::two_to_one(a, b);
        let d = H::two_to_one(
            self.proposed_world_state_digest,
            self.approved_world_state_digest,
        );
        let e = H::two_to_one(c, d);

        H::two_to_one(self.block_headers_digest, e)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use plonky2::{field::goldilocks_field::GoldilocksField, hash::{poseidon::PoseidonHash, hash_types::HashOut}};

    use crate::{
        merkle_tree::tree::{get_merkle_proof, get_merkle_proof_with_zero},
        rollup::block::{calc_merkle_root_with_hasher, BlockHeaderPoseidon, BlockHeaderWithHasher},
        sparse_merkle_tree::goldilocks_poseidon::WrappedHashOut,
        transaction::block_header::{get_block_hash, BlockHeader},
    };

    #[test]
    fn test_calc_merkle_root() {
        let default_tx_hash: HashOut<GoldilocksField> = HashOut::ZERO;
        let transaction_hashes = vec![
            *WrappedHashOut::from_str(
                "0xef4bfcb3c4c43d0d5b776beb86595301fc4def55d6d5f7ecb763749e24b1ce45",
            )
            .unwrap(),
            *WrappedHashOut::from_str(
                "0x6aec6200eaaf7be85283015b7ef20f1078d1d54a4089d62c7507a4e67b4071d1",
            )
            .unwrap(),
            *WrappedHashOut::from_str(
                "0xfdcb4ab40c969024683d280e55985f950a11853636d1bd7181221cc914963121",
            )
            .unwrap(),
        ];
        let root = calc_merkle_root_with_hasher::<GoldilocksField, PoseidonHash>(
            &transaction_hashes,
            1,
            3,
            default_tx_hash,
        );
        let root2 = *get_merkle_proof_with_zero(
            &transaction_hashes
                .iter()
                .cloned()
                .map(|v| WrappedHashOut::from(v))
                .collect::<Vec<_>>(),
            1,
            3,
            default_tx_hash.into(),
        ).root;

        assert_eq!(root, root2);
    }

    #[test]
    fn test_block_hash() {
        let block_header: BlockHeader<GoldilocksField> = BlockHeader {
            block_number: 1870210342,
            prev_block_hash: *WrappedHashOut::from_str(
                "0xef4bfcb3c4c43d0d5b776beb86595301fc4def55d6d5f7ecb763749e24b1ce45",
            )
            .unwrap(),
            block_headers_digest: *WrappedHashOut::from_str(
                "0x6aec6200eaaf7be85283015b7ef20f1078d1d54a4089d62c7507a4e67b4071d1",
            )
            .unwrap(),
            transactions_digest: *WrappedHashOut::from_str(
                "0xfdcb4ab40c969024683d280e55985f950a11853636d1bd7181221cc914963121",
            )
            .unwrap(),
            deposit_digest: *WrappedHashOut::from_str(
                "0x810319987795e36ffd61ebd87cecaecd6fed4f754f08b5c6ecffbdf82eaa9928",
            )
            .unwrap(),
            proposed_world_state_digest: *WrappedHashOut::from_str(
                "0x664e38d63a0f3f8a7487c4d0676b8f4a6a651c6e3355e93d6e23ef53fd315d5e",
            )
            .unwrap(),
            approved_world_state_digest: *WrappedHashOut::from_str(
                "0x85933162c2e19c407ad54388e5aa7deaa91848bf1cfbe945cf71fb1c4295dfa4",
            )
            .unwrap(),
            latest_account_digest: *WrappedHashOut::from_str(
                "0xa3bbe6909fd1782b0d7019fff0f081a5ebfc5a7dc1d8cbe227e12b92ffb79911",
            )
            .unwrap(),
        };

        let block_hash = get_block_hash(&block_header);
        let block_hash2 = BlockHeaderPoseidon::from(block_header).block_hash();
        assert_eq!(block_hash, block_hash2);
    }
}
