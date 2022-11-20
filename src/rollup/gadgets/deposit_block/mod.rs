use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use serde::{Deserialize, Serialize};

use crate::{
    sparse_merkle_tree::{
        gadgets::{
            common::conditionally_select,
            process::{
                process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
                utils::{
                    get_process_merkle_proof_role, verify_layered_smt_connection,
                    ProcessMerkleProofRoleTarget,
                },
            },
        },
        goldilocks_poseidon::GoldilocksHashOut,
    },
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositInfo<F: Field> {
    pub receiver_address: Address<F>,
    pub contract_address: Address<F>,
    pub variable_index: HashOut<F>,
    pub amount: F,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableDepositInfo {
    pub receiver_address: GoldilocksHashOut,
    pub contract_address: GoldilocksHashOut,
    pub variable_index: GoldilocksHashOut,
    pub amount: GoldilocksField,
}

impl From<SerializableDepositInfo> for DepositInfo<GoldilocksField> {
    fn from(value: SerializableDepositInfo) -> Self {
        Self {
            receiver_address: Address(value.receiver_address.0),
            contract_address: Address(value.contract_address.0),
            variable_index: value.variable_index.0,
            amount: value.amount,
        }
    }
}

impl<'de> Deserialize<'de> for DepositInfo<GoldilocksField> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = SerializableDepositInfo::deserialize(deserializer)?;

        Ok(raw.into())
    }
}

impl From<DepositInfo<GoldilocksField>> for SerializableDepositInfo {
    fn from(value: DepositInfo<GoldilocksField>) -> Self {
        SerializableDepositInfo {
            receiver_address: value.receiver_address.0.into(),
            contract_address: value.contract_address.0.into(),
            variable_index: value.variable_index.into(),
            amount: value.amount,
        }
    }
}

impl Serialize for DepositInfo<GoldilocksField> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = SerializableDepositInfo::from(*self);

        raw.serialize(serializer)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DepositInfoTarget {
    pub receiver_address: AddressTarget,
    pub contract_address: AddressTarget,
    pub variable_index: HashOutTarget,
    pub amount: Target,
}

impl DepositInfoTarget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let receiver_address = AddressTarget::add_virtual_to(builder);
        let contract_address = AddressTarget::add_virtual_to(builder);
        let variable_index = builder.add_virtual_hash();
        let amount = builder.add_virtual_target();

        Self {
            receiver_address,
            contract_address,
            variable_index,
            amount,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut impl Witness<F>,
        value: DepositInfo<F>,
    ) {
        self.receiver_address
            .set_witness(pw, value.receiver_address);
        self.contract_address
            .set_witness(pw, value.contract_address);
        pw.set_hash_target(self.variable_index, value.variable_index);
        pw.set_target(self.amount, value.amount);
    }
}

#[derive(Clone, Debug)]
pub struct DepositBlockProofTarget<
    const D: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_DEPOSITS: usize,
> {
    pub deposit_process_proofs: [(
        SparseMerkleProcessProofTarget<N_LOG_RECIPIENTS>,
        SparseMerkleProcessProofTarget<N_LOG_CONTRACTS>,
        SparseMerkleProcessProofTarget<N_LOG_VARIABLES>,
    ); N_DEPOSITS], // input

    pub deposit_digest: HashOutTarget, // output
}

impl<
        const D: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_LOG_CONTRACTS: usize,
        const N_LOG_VARIABLES: usize,
        const N_DEPOSITS: usize,
    > DepositBlockProofTarget<D, N_LOG_RECIPIENTS, N_LOG_CONTRACTS, N_LOG_VARIABLES, N_DEPOSITS>
{
    pub fn add_virtual_to<F: RichField + Extendable<D>, H: AlgebraicHasher<F>>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let mut deposit_process_proofs = vec![];
        for _ in 0..N_DEPOSITS {
            let targets = (
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder),
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder),
                SparseMerkleProcessProofTarget::add_virtual_to::<F, H, D>(builder),
            );

            deposit_process_proofs.push(targets);
        }

        let deposit_digest = deposit_process_proofs.last().unwrap().0.new_root;

        Self {
            deposit_process_proofs: deposit_process_proofs.try_into().unwrap(),
            deposit_digest,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, H: AlgebraicHasher<F>>(
        &self,
        pw: &mut impl Witness<F>,
        deposit_process_proofs: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
    ) {
        assert!(deposit_process_proofs.len() <= self.deposit_process_proofs.len());
        for (proof_t, proof) in self
            .deposit_process_proofs
            .iter()
            .zip(deposit_process_proofs.iter())
        {
            proof_t.0.set_witness(pw, &proof.0);
            proof_t.1.set_witness(pw, &proof.1);
            proof_t.2.set_witness(pw, &proof.2);
        }

        let latest_root = deposit_process_proofs.last().unwrap().0.new_root;
        let zero = F::ZERO;
        let default_hash = HashOut {
            elements: [zero; 4],
        };
        let default_proof = SmtProcessProof {
            old_root: default_hash.into(),
            old_key: default_hash.into(),
            old_value: default_hash.into(),
            new_root: default_hash.into(),
            new_key: default_hash.into(),
            new_value: default_hash.into(),
            siblings: vec![],
            is_old0: true,
            fnc: crate::sparse_merkle_tree::proof::ProcessMerkleProofRole::ProcessNoOp,
        };
        let mut default_proof0 = default_proof.clone();
        default_proof0.old_root = latest_root;
        default_proof0.new_root = latest_root;
        for proof_t in self
            .deposit_process_proofs
            .iter()
            .skip(deposit_process_proofs.len())
        {
            proof_t.0.set_witness(pw, &default_proof0);
            proof_t.1.set_witness(pw, &default_proof);
            proof_t.2.set_witness(pw, &default_proof);
        }
    }
}

/// Returns `(block_tx_root, old_world_state_root, new_world_state_root)`
pub fn calc_deposit_digest<
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    const D: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    deposit_process_proofs: &[(
        SparseMerkleProcessProofTarget<N_LOG_RECIPIENTS>,
        SparseMerkleProcessProofTarget<N_LOG_CONTRACTS>,
        SparseMerkleProcessProofTarget<N_LOG_VARIABLES>,
    )],
) -> HashOutTarget {
    let zero = builder.zero();
    let mut deposit_digest = HashOutTarget {
        elements: [zero; 4],
    };
    for proof_t in deposit_process_proofs {
        let ProcessMerkleProofRoleTarget {
            is_insert_or_no_op,
            is_no_op,
            ..
        } = get_process_merkle_proof_role(builder, proof_t.2.fnc);
        let constant_true = builder._true();
        builder.connect(is_insert_or_no_op.target, constant_true.target);
        verify_layered_smt_connection(
            builder,
            proof_t.0.fnc,
            proof_t.0.old_value,
            proof_t.0.new_value,
            proof_t.1.old_root,
            proof_t.1.new_root,
        );
        verify_layered_smt_connection(
            builder,
            proof_t.1.fnc,
            proof_t.1.old_value,
            proof_t.1.new_value,
            proof_t.2.old_root,
            proof_t.2.new_root,
        );

        builder.connect_hashes(proof_t.0.old_root, deposit_digest);

        deposit_digest =
            conditionally_select(builder, deposit_digest, proof_t.0.new_root, is_no_op);
    }

    deposit_digest
}
