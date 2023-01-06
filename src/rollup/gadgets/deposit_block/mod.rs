use std::str::FromStr;

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use serde::{Deserialize, Serialize};

use crate::{
    sparse_merkle_tree::{
        gadgets::process::{
            process_smt::{SmtProcessProof, SparseMerkleProcessProofTarget},
            utils::{
                get_process_merkle_proof_role, verify_layered_smt_target_connection,
                ProcessMerkleProofRoleTarget,
            },
        },
        goldilocks_poseidon::WrappedHashOut,
        layered_tree::verify_layered_smt_connection,
        proof::ProcessMerkleProofRole,
    },
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VariableIndex<F>(pub u8, core::marker::PhantomData<F>);

impl<F: Field> From<u8> for VariableIndex<F> {
    fn from(value: u8) -> Self {
        Self(value, core::marker::PhantomData)
    }
}

impl<F: RichField> VariableIndex<F> {
    pub fn to_hash_out(&self) -> HashOut<F> {
        HashOut::from_partial(&[F::from_canonical_u8(self.0)])
    }

    pub fn from_hash_out(value: HashOut<F>) -> Self {
        Self::read(&mut value.elements.iter())
    }

    pub fn read(inputs: &mut core::slice::Iter<F>) -> Self {
        let value = WrappedHashOut::read(inputs).0.elements[0].to_canonical_u64() as u8;

        value.into()
    }

    pub fn write(&self, inputs: &mut Vec<F>) {
        inputs.append(&mut self.to_hash_out().elements.to_vec());
    }
}

impl<F: RichField> std::fmt::Display for VariableIndex<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for VariableIndex<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

#[test]
fn test_fmt_variable_index() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    let value = VariableIndex::from(20u8);
    let encoded_value = format!("{}", value);
    assert_eq!(encoded_value, "0x14");
    let decoded_value: VariableIndex<GoldilocksField> = VariableIndex::from_str("0x14").unwrap();
    assert_eq!(decoded_value, value);
}

// #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
// #[repr(transparent)]
// pub struct SerializableVariableIndex(#[serde(with = "SerHex::<StrictPfx>")] pub u8);

// impl<F: RichField> From<SerializableVariableIndex> for VariableIndex<F> {
//     fn from(value: SerializableVariableIndex) -> Self {
//         value.0.into()
//     }
// }

impl<'de, F: RichField> Deserialize<'de> for VariableIndex<F> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let raw_without_prefix = raw.strip_prefix("0x").ok_or_else(|| {
            serde::de::Error::custom(format!(
                "fail to strip 0x-prefix: given value {raw} does not start with 0x"
            ))
        })?;
        let bytes = hex::decode(raw_without_prefix).map_err(|err| {
            serde::de::Error::custom(format!("fail to parse a hex string: {err}"))
        })?;
        let raw = *bytes.first().ok_or_else(|| {
            serde::de::Error::custom(format!("out of index: given value {raw} is too short"))
        })?;

        Ok(raw.into())
    }
}

// impl<F: RichField> From<VariableIndex<F>> for SerializableVariableIndex {
//     fn from(value: VariableIndex<F>) -> Self {
//         SerializableVariableIndex(value.0)
//     }
// }

impl<F: RichField> Serialize for VariableIndex<F> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = [self.0];
        let raw = format!("0x{}", hex::encode(bytes));

        raw.serialize(serializer)
    }
}

#[test]
fn test_serde_variable_index() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    let value: VariableIndex<GoldilocksField> = 20u8.into();
    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: VariableIndex<GoldilocksField> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, value);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "F: RichField")]
pub struct DepositInfo<F: Field> {
    pub receiver_address: Address<F>,
    pub contract_address: Address<F>,
    pub variable_index: VariableIndex<F>,
    pub amount: F,
}

#[test]
fn test_serde_deposit_info() {
    use plonky2::field::goldilocks_field::GoldilocksField;

    let deposit_info: DepositInfo<GoldilocksField> = DepositInfo::default();
    let _json = serde_json::to_string(&deposit_info).unwrap();
    let json = "{\"receiver_address\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"contract_address\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"variable_index\":\"0x00\",\"amount\":0}";
    let decoded_deposit_info: DepositInfo<_> = serde_json::from_str(json).unwrap();
    assert_eq!(decoded_deposit_info, deposit_info);

    let json_value = serde_json::to_value(deposit_info).unwrap();
    let decoded_deposit_info: DepositInfo<_> = serde_json::from_value(json_value).unwrap();
    assert_eq!(decoded_deposit_info, deposit_info);
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
        pw.set_hash_target(self.variable_index, value.variable_index.to_hash_out());
        pw.set_target(self.amount, value.amount);
    }
}

#[derive(Clone, Debug)]
pub struct DepositBlockProductionTarget<
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

    pub interior_deposit_digest: HashOutTarget, // output
}

impl<
        const D: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_LOG_CONTRACTS: usize,
        const N_LOG_VARIABLES: usize,
        const N_DEPOSITS: usize,
    >
    DepositBlockProductionTarget<D, N_LOG_RECIPIENTS, N_LOG_CONTRACTS, N_LOG_VARIABLES, N_DEPOSITS>
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

        let interior_deposit_digest =
            calc_deposit_digest::<F, H, D, N_LOG_RECIPIENTS, N_LOG_CONTRACTS, N_LOG_VARIABLES>(
                builder,
                &deposit_process_proofs,
            );

        Self {
            deposit_process_proofs: deposit_process_proofs.try_into().unwrap(),
            interior_deposit_digest,
        }
    }

    /// Returns `interior_deposit_digest`
    pub fn set_witness<F: RichField + Extendable<D>>(
        &self,
        pw: &mut impl Witness<F>,
        deposit_process_proofs: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
    ) -> WrappedHashOut<F> {
        let mut prev_interior_deposit_digest = WrappedHashOut::default();
        assert!(deposit_process_proofs.len() <= self.deposit_process_proofs.len());
        for (proof_t, proof) in self
            .deposit_process_proofs
            .iter()
            .zip(deposit_process_proofs.iter())
        {
            assert_eq!(proof.0.old_root, prev_interior_deposit_digest);
            verify_layered_smt_connection(
                proof.0.fnc,
                proof.0.old_value,
                proof.0.new_value,
                proof.1.old_root,
                proof.1.new_root,
            )
            .unwrap();
            verify_layered_smt_connection(
                proof.1.fnc,
                proof.1.old_value,
                proof.1.new_value,
                proof.2.old_root,
                proof.2.new_root,
            )
            .unwrap();
            assert_eq!(proof.2.fnc, ProcessMerkleProofRole::ProcessInsert);

            proof_t.0.set_witness(pw, &proof.0);
            proof_t.1.set_witness(pw, &proof.1);
            proof_t.2.set_witness(pw, &proof.2);

            prev_interior_deposit_digest = proof.0.new_root;
        }
        let interior_deposit_digest = prev_interior_deposit_digest;

        let default_proof = SmtProcessProof::with_root(Default::default());
        let default_proof0 = SmtProcessProof::with_root(interior_deposit_digest);
        for proof_t in self
            .deposit_process_proofs
            .iter()
            .skip(deposit_process_proofs.len())
        {
            proof_t.0.set_witness(pw, &default_proof0);
            proof_t.1.set_witness(pw, &default_proof);
            proof_t.2.set_witness(pw, &default_proof);
        }

        interior_deposit_digest
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
    let mut interior_deposit_digest = HashOutTarget {
        elements: [zero; 4],
    };
    for proof_t in deposit_process_proofs {
        let ProcessMerkleProofRoleTarget {
            is_insert_or_no_op, ..
        } = get_process_merkle_proof_role(builder, proof_t.2.fnc);
        let constant_true = builder._true();
        builder.connect(is_insert_or_no_op.target, constant_true.target);
        verify_layered_smt_target_connection(
            builder,
            proof_t.0.fnc,
            proof_t.0.old_value,
            proof_t.0.new_value,
            proof_t.1.old_root,
            proof_t.1.new_root,
        );
        verify_layered_smt_target_connection(
            builder,
            proof_t.1.fnc,
            proof_t.1.old_value,
            proof_t.1.new_value,
            proof_t.2.old_root,
            proof_t.2.new_root,
        );

        builder.connect_hashes(proof_t.0.old_root, interior_deposit_digest);
        interior_deposit_digest = proof_t.0.new_root;
    }

    interior_deposit_digest
}

#[test]
fn test_deposit_block() {
    use std::time::Instant;

    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, Field64},
        },
        hash::hash_types::HashOut,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        rollup::gadgets::deposit_block::DepositInfo,
        sparse_merkle_tree::goldilocks_poseidon::{
            GoldilocksHashOut, LayeredLayeredPoseidonSparseMerkleTree, NodeDataMemory, RootDataTmp,
        },
        zkdsa::account::{private_key_to_account, Address},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const N_LOG_RECIPIENTS: usize = 3;
    const N_LOG_CONTRACTS: usize = 3;
    const N_LOG_VARIABLES: usize = 3;
    const N_DEPOSITS: usize = 2;

    let sender2_private_key = HashOut {
        elements: [
            F::from_canonical_u64(15657143458229430356),
            F::from_canonical_u64(6012455030006979790),
            F::from_canonical_u64(4280058849535143691),
            F::from_canonical_u64(5153662694263190591),
        ],
    };
    let sender2_account = private_key_to_account(sender2_private_key);
    let sender2_address = sender2_account.address.0;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_gate_row = Some(529); // xors in SparseMerkleProcessProof in DepositBlock

    // deposit block
    let deposit_block_target: DepositBlockProductionTarget<
        D,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_DEPOSITS,
    > = DepositBlockProductionTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher>(
        &mut builder,
    );
    builder.register_public_inputs(&deposit_block_target.interior_deposit_digest.elements);
    let circuit_data = builder.build::<C>();

    let deposit_list: Vec<DepositInfo<F>> = vec![DepositInfo {
        receiver_address: Address(sender2_address),
        contract_address: Address(*GoldilocksHashOut::from_u128(1)),
        variable_index: 0u8.into(),
        amount: GoldilocksField::from_noncanonical_u64(1),
    }];

    let mut deposit_tree = LayeredLayeredPoseidonSparseMerkleTree::new(
        NodeDataMemory::default(),
        RootDataTmp::default(),
    );
    let deposit_process_proofs = deposit_list
        .iter()
        .map(|leaf| {
            deposit_tree
                .set(
                    leaf.receiver_address.0.into(),
                    leaf.contract_address.0.into(),
                    leaf.variable_index.to_hash_out().into(),
                    HashOut::from_partial(&[leaf.amount]).into(),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();

    let mut pw = PartialWitness::new();
    let interior_deposit_digest =
        deposit_block_target.set_witness(&mut pw, &deposit_process_proofs);

    println!("start proving: block_proof");
    let start = Instant::now();
    let deposit_block_proof = circuit_data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    assert_eq!(
        [interior_deposit_digest.elements].concat(),
        deposit_block_proof.public_inputs
    );

    circuit_data.verify(deposit_block_proof).unwrap();

    let mut pw = PartialWitness::new();
    let default_interior_deposit_digest = deposit_block_target.set_witness(&mut pw, &[]);

    println!("start proving: block_proof");
    let start = Instant::now();
    let default_deposit_block_proof = circuit_data.prove(pw).unwrap();
    let end = start.elapsed();
    println!("prove: {}.{:03} sec", end.as_secs(), end.subsec_millis());

    assert_eq!(
        [default_interior_deposit_digest.elements].concat(),
        default_deposit_block_proof.public_inputs
    );

    circuit_data.verify(default_deposit_block_proof).unwrap();
}
