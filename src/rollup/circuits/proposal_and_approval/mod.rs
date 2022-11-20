use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
        proof::{Proof, ProofWithPublicInputs},
    },
};

use crate::{
    merkle_tree::gadgets::{get_merkle_root_target, MerkleProofTarget},
    sparse_merkle_tree::gadgets::process::process_smt::SmtProcessProof,
    transaction::gadgets::block_header::{get_block_hash_target, BlockHeaderTarget},
    zkdsa::{account::Address, gadgets::account::AddressTarget},
};

use super::super::gadgets::{
    approval_block::ApprovalBlockProofTarget,
    deposit_block::{DepositBlockProofTarget, DepositInfo, DepositInfoTarget},
    proposal_block::ProposalBlockProofTarget,
};
use super::merge_and_purge::MergeAndPurgeTransitionProofWithPublicInputs;

type C = PoseidonGoldilocksConfig;
type H = <C as GenericConfig<D>>::InnerHasher;
type F = <C as GenericConfig<D>>::F;
const D: usize = 2;

pub struct OneBlockProofTarget<
    const D: usize,
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_TXS: usize,
    const N_DEPOSITS: usize,
> {
    pub deposit_block_target:
        DepositBlockProofTarget<D, N_LOG_RECIPIENTS, N_LOG_CONTRACTS, N_LOG_VARIABLES, N_DEPOSITS>,
    pub proposal_block_target: ProposalBlockProofTarget<D, N_LOG_USERS, N_LOG_TXS, N_TXS>,
    pub approval_block_target: ApprovalBlockProofTarget<D, N_LOG_USERS, N_LOG_TXS, N_TXS>,
    pub block_number: Target,
    pub prev_block_header_proof: MerkleProofTarget<32>,
    pub prev_block_hash: HashOutTarget,
    pub block_header: BlockHeaderTarget,
}

impl<
        const D: usize,
        const N_LOG_USERS: usize,
        const N_LOG_TXS: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_LOG_CONTRACTS: usize,
        const N_LOG_VARIABLES: usize,
        const N_TXS: usize,
        const N_DEPOSITS: usize,
    >
    OneBlockProofTarget<
        D,
        N_LOG_USERS,
        N_LOG_TXS,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_TXS,
        N_DEPOSITS,
    >
{
    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut impl Witness<F>,
        block_number: u32,
        user_tx_proofs: &[MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>],
        deposit_process_proofs: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
        world_state_process_proofs: &[SmtProcessProof<F>],
        world_state_revert_proofs: &[SmtProcessProof<F>],
        received_signatures: &[ProofWithPublicInputs<F, C, D>],
        latest_account_tree_process_proofs: &[SmtProcessProof<F>],
        block_header_siblings: &[HashOut<F>],
        prev_block_hash: HashOut<F>,
        old_world_state_root: HashOut<F>,
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        self.deposit_block_target
            .set_witness::<F, H>(pw, deposit_process_proofs);
        self.proposal_block_target.set_witness(
            pw,
            world_state_process_proofs,
            &user_tx_proofs
                .iter()
                .map(|p| ProofWithPublicInputs::from(p.clone()))
                .collect::<Vec<_>>(),
            old_world_state_root,
        );
        self.approval_block_target.set_witness(
            pw,
            block_number,
            world_state_revert_proofs,
            &user_tx_proofs
                .iter()
                .map(|p| ProofWithPublicInputs::from(p.clone()))
                .collect::<Vec<_>>(),
            received_signatures,
            latest_account_tree_process_proofs,
        );

        self.prev_block_header_proof.set_witness(
            pw,
            F::from_canonical_u32(block_number - 1),
            prev_block_hash,
            block_header_siblings,
        );

        pw.set_target(
            self.block_header.block_number,
            F::from_canonical_u32(block_number),
        );

        pw.set_hash_target(self.prev_block_hash, prev_block_hash);
    }
}

pub fn make_block_proof_circuit<
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_TXS: usize,
    const N_DEPOSITS: usize,
>(
    merge_and_purge_circuit_data: CircuitData<F, C, D>,
    zkdsa_circuit_data: CircuitData<F, C, D>,
) -> ProposalAndApprovalBlockCircuit<
    N_LOG_USERS,
    N_LOG_TXS,
    N_LOG_RECIPIENTS,
    N_LOG_CONTRACTS,
    N_LOG_VARIABLES,
    N_TXS,
    N_DEPOSITS,
> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_gate_row = Some(461); // xors in SparseMerkleProcessProof in DepositBlock

    // deposit block
    let deposit_block_target: DepositBlockProofTarget<
        D,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_DEPOSITS,
    > = DepositBlockProofTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher>(&mut builder);

    // proposal block
    let proposal_block_target: ProposalBlockProofTarget<D, N_LOG_USERS, N_LOG_TXS, N_TXS> =
        ProposalBlockProofTarget::add_virtual_to::<F, C>(
            &mut builder,
            &merge_and_purge_circuit_data,
        );

    // approval block
    let approval_block_target: ApprovalBlockProofTarget<D, N_LOG_USERS, N_LOG_TXS, N_TXS> =
        ApprovalBlockProofTarget::add_virtual_to::<F, C>(
            &mut builder,
            &merge_and_purge_circuit_data,
            &zkdsa_circuit_data,
        );

    for (_account_tree_process_proof, received_signature) in approval_block_target
        .account_tree_process_proofs
        .iter()
        .zip_eq(approval_block_target.received_signatures.iter())
    {
        let account_id = received_signature.inner.public_inputs[4];
        // let last_block_number = account_tree_process_proof.old_value.elements[0];
        let cancel_flag = builder.not(received_signature.enabled);

        // publish ID list
        // public_inputs[(3*i)..(3*i+3)]
        builder.register_public_input(account_id);
        // builder.register_public_input(last_block_number);
        builder.register_public_input(cancel_flag.target);
    }

    for proof_t in deposit_block_target.deposit_process_proofs.iter() {
        let receiver_address_t = proof_t.0.new_key;
        let contract_address_t = proof_t.1.new_key;
        let variable_index_t = proof_t.2.new_key;
        let amount_t = proof_t.2.new_value;
        builder.register_public_inputs(&receiver_address_t.elements);
        builder.register_public_inputs(&contract_address_t.elements);
        builder.register_public_inputs(&variable_index_t.elements);
        builder.register_public_input(amount_t.elements[0]);
    }

    builder.register_public_inputs(&approval_block_target.old_account_tree_root.elements); // public_inputs[(3*N_TXS)..(3*N_TXS+4)]
    builder.register_public_inputs(&approval_block_target.new_account_tree_root.elements); // public_inputs[(3*N_TXS+4)..(3*N_TXS+8)]

    builder.register_public_inputs(&proposal_block_target.old_world_state_root.elements); // public_inputs[(3*N_TXS+8)..(3*N_TXS+12)]
    builder.register_public_inputs(&proposal_block_target.new_world_state_root.elements); // public_inputs[(3*N_TXS+12)..(3*N_TXS+16)]

    // block header
    let block_number = builder.add_virtual_target();
    builder.range_check(block_number, 32);
    let transactions_digest = proposal_block_target.block_tx_root;
    let deposit_digest = deposit_block_target.deposit_digest;
    let proposed_world_state_digest = proposal_block_target.new_world_state_root;
    let approved_world_state_digest = approval_block_target.new_world_state_root;
    let latest_account_digest = approval_block_target.new_account_tree_root;

    // `block_number -　1` までの block header で block header tree を作る.
    let prev_block_header_proof: MerkleProofTarget<32> =
        MerkleProofTarget::add_virtual_to::<F, H, D>(&mut builder);
    let prev_block_hash = builder.add_virtual_hash();
    let prev_block_header_digest = get_merkle_root_target::<F, H, D>(
        &mut builder,
        prev_block_header_proof.index,
        prev_block_hash,
        &prev_block_header_proof.siblings,
    );

    let block_header = BlockHeaderTarget {
        block_number,
        prev_block_header_digest,
        transactions_digest,
        deposit_digest,
        proposed_world_state_digest,
        approved_world_state_digest,
        latest_account_digest,
    };
    let block_hash = get_block_hash_target::<F, H, D>(&mut builder, &block_header);

    builder.register_public_inputs(&prev_block_header_proof.root.elements); // old_root
    builder.register_public_inputs(&prev_block_header_digest.elements); // new_root
    builder.register_public_inputs(&block_hash.elements);
    let block_circuit_data = builder.build::<C>();

    let targets = OneBlockProofTarget {
        proposal_block_target,
        approval_block_target,
        deposit_block_target,
        block_number,
        prev_block_header_proof,
        prev_block_hash,
        block_header,
    };

    ProposalAndApprovalBlockCircuit {
        data: block_circuit_data,
        targets,
    }
}

pub struct ProposalAndApprovalBlockCircuit<
    const N_LOG_USERS: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_TXS: usize,
    const N_DEPOSITS: usize,
> {
    pub data: CircuitData<F, C, D>,
    pub targets: OneBlockProofTarget<
        D,
        N_LOG_USERS,
        N_LOG_TXS,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_TXS,
        N_DEPOSITS,
    >,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestAccountInfo<F: Field> {
    pub account_id: F,
    // pub last_block_number: F,
    pub cancel_flag: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalAndApprovalBlockPublicInputs<F: RichField> {
    pub address_list: Vec<LatestAccountInfo<F>>,
    pub deposit_list: Vec<DepositInfo<F>>,
    pub old_account_tree_root: HashOut<F>,
    pub new_account_tree_root: HashOut<F>,
    pub old_world_state_root: HashOut<F>,
    pub new_world_state_root: HashOut<F>,
    pub old_prev_block_header_digest: HashOut<F>,
    pub new_prev_block_header_digest: HashOut<F>,
    pub block_hash: HashOut<F>,
}

impl<F: RichField> ProposalAndApprovalBlockPublicInputs<F> {
    pub fn encode(&self) -> Vec<F> {
        let mut public_inputs = vec![];
        for LatestAccountInfo {
            account_id,
            // last_block_number,
            cancel_flag,
        } in self.address_list.clone()
        {
            public_inputs.push(account_id);
            // public_inputs.push(last_block_number);
            public_inputs.push(F::from_bool(cancel_flag));
        }

        for DepositInfo {
            receiver_address,
            contract_address,
            variable_index,
            amount,
        } in self.deposit_list.clone()
        {
            receiver_address.write(&mut public_inputs);
            contract_address.write(&mut public_inputs);
            public_inputs.append(&mut variable_index.elements.into());
            public_inputs.push(amount);
        }

        public_inputs.append(&mut self.old_account_tree_root.elements.into());
        public_inputs.append(&mut self.new_account_tree_root.elements.into());
        public_inputs.append(&mut self.old_world_state_root.elements.into());
        public_inputs.append(&mut self.new_world_state_root.elements.into());

        public_inputs.append(&mut self.old_prev_block_header_digest.elements.into());
        public_inputs.append(&mut self.new_prev_block_header_digest.elements.into());
        public_inputs.append(&mut self.block_hash.elements.into());

        public_inputs
    }
}

#[derive(Clone, Debug)]
pub struct ProposalAndApprovalBlockPublicInputsTarget<const N_TXS: usize, const N_DEPOSITS: usize> {
    pub address_list: [LatestAccountInfoTarget; N_TXS],
    pub deposit_list: [DepositInfoTarget; N_DEPOSITS],
    pub old_account_tree_root: HashOutTarget,
    pub new_account_tree_root: HashOutTarget,
    pub old_world_state_root: HashOutTarget,
    pub new_world_state_root: HashOutTarget,
    pub old_prev_block_header_digest: HashOutTarget,
    pub new_prev_block_header_digest: HashOutTarget,
    pub block_hash: HashOutTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalAndApprovalBlockProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: Proof<F, C, D>,
    pub public_inputs: ProposalAndApprovalBlockPublicInputs<F>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    From<ProposalAndApprovalBlockProofWithPublicInputs<F, C, D>>
    for ProofWithPublicInputs<F, C, D>
{
    fn from(
        value: ProposalAndApprovalBlockProofWithPublicInputs<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        ProofWithPublicInputs {
            proof: value.proof,
            public_inputs: value.public_inputs.encode(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LatestAccountInfoTarget {
    pub account_id: Target,
    // pub last_block_number: Target,
    pub cancel_flag: BoolTarget,
}

pub fn parse_proposal_and_approval_public_inputs<const N_TXS: usize, const N_DEPOSITS: usize>(
    public_inputs_t: &[Target],
) -> ProposalAndApprovalBlockPublicInputsTarget<N_TXS, N_DEPOSITS> {
    let mut public_inputs_t = public_inputs_t.iter();
    let address_list = (0..N_TXS)
        .map(|_| LatestAccountInfoTarget {
            account_id: *public_inputs_t.next().unwrap(),
            // last_block_number: *public_inputs_t.next().unwrap(),
            cancel_flag: BoolTarget::new_unsafe(*public_inputs_t.next().unwrap()),
        })
        .collect::<Vec<_>>();

    let deposit_list = (0..N_DEPOSITS)
        .map(|_| DepositInfoTarget {
            receiver_address: AddressTarget::read(&mut public_inputs_t),
            contract_address: AddressTarget::read(&mut public_inputs_t),
            variable_index: HashOutTarget {
                elements: [
                    *public_inputs_t.next().unwrap(),
                    *public_inputs_t.next().unwrap(),
                    *public_inputs_t.next().unwrap(),
                    *public_inputs_t.next().unwrap(),
                ],
            },
            amount: *public_inputs_t.next().unwrap(),
        })
        .collect::<Vec<_>>();

    let old_account_tree_root = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };
    let new_account_tree_root = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };

    let old_world_state_root = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };
    let new_world_state_root = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };
    let old_prev_block_header_digest = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };
    let new_prev_block_header_digest = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };
    let block_hash = HashOutTarget {
        elements: [
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
            *public_inputs_t.next().unwrap(),
        ],
    };

    let rest_public_inputs = public_inputs_t.collect::<Vec<_>>();
    dbg!(rest_public_inputs);

    ProposalAndApprovalBlockPublicInputsTarget {
        address_list: address_list.try_into().unwrap(),
        deposit_list: deposit_list.try_into().unwrap(),
        old_account_tree_root,
        new_account_tree_root,
        old_world_state_root,
        new_world_state_root,
        old_prev_block_header_digest,
        new_prev_block_header_digest,
        block_hash,
    }
}

impl<
        const N_LOG_USERS: usize,
        const N_LOG_TXS: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_LOG_CONTRACTS: usize,
        const N_LOG_VARIABLES: usize,
        const N_TXS: usize,
        const N_DEPOSITS: usize,
    >
    ProposalAndApprovalBlockCircuit<
        N_LOG_USERS,
        N_LOG_TXS,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_TXS,
        N_DEPOSITS,
    >
{
    pub fn parse_public_inputs(
        &self,
    ) -> ProposalAndApprovalBlockPublicInputsTarget<N_TXS, N_DEPOSITS> {
        let public_inputs_t = self.data.prover_only.public_inputs.clone();

        parse_proposal_and_approval_public_inputs::<N_TXS, N_DEPOSITS>(&public_inputs_t)
    }

    pub fn prove(
        &self,
        inputs: PartialWitness<F>,
    ) -> anyhow::Result<ProposalAndApprovalBlockProofWithPublicInputs<F, C, D>> {
        let proof_with_pis = self.data.prove(inputs)?;
        let mut public_inputs = proof_with_pis.public_inputs.iter();
        let address_list = (0..N_TXS)
            .map(|_| LatestAccountInfo {
                account_id: *public_inputs.next().unwrap(),
                // last_block_number: *public_inputs.next().unwrap(),
                cancel_flag: public_inputs.next().unwrap().is_nonzero(),
            })
            .collect::<Vec<_>>();
        let deposit_list = (0..N_DEPOSITS)
            .map(|_| DepositInfo {
                receiver_address: Address::read(&mut public_inputs),
                contract_address: Address::read(&mut public_inputs),
                variable_index: HashOut {
                    elements: [
                        *public_inputs.next().unwrap(),
                        *public_inputs.next().unwrap(),
                        *public_inputs.next().unwrap(),
                        *public_inputs.next().unwrap(),
                    ],
                },
                amount: *public_inputs.next().unwrap(),
            })
            .collect::<Vec<_>>();
        let old_account_tree_root = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };
        let new_account_tree_root = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };

        let old_world_state_root = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };
        let new_world_state_root = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };
        let old_prev_block_header_digest = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };
        let new_prev_block_header_digest = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };
        let block_hash = HashOut {
            elements: [
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
                *public_inputs.next().unwrap(),
            ],
        };

        assert_eq!(public_inputs.next(), None);

        Ok(ProposalAndApprovalBlockProofWithPublicInputs {
            proof: proof_with_pis.proof,
            public_inputs: ProposalAndApprovalBlockPublicInputs {
                address_list,
                deposit_list,
                old_account_tree_root,
                new_account_tree_root,
                old_world_state_root,
                new_world_state_root,
                old_prev_block_header_digest,
                new_prev_block_header_digest,
                block_hash,
            },
        })
    }

    pub fn verify(
        &self,
        proof_with_pis: ProposalAndApprovalBlockProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        let public_inputs = proof_with_pis.public_inputs.encode();

        self.data.verify(ProofWithPublicInputs {
            proof: proof_with_pis.proof,
            public_inputs,
        })
    }
}
