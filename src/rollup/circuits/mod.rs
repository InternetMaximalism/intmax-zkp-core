use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{Proof, ProofWithPublicInputs},
    },
};

use crate::{
    merkle_tree::gadgets::{get_merkle_root_target, MerkleProofTarget},
    recursion::gadgets::RecursiveProofTarget,
    rollup::gadgets::{
        approval_block::ApprovalBlockProofTarget,
        deposit_block::{DepositBlockProofTarget, DepositInfo, DepositInfoTarget, VariableIndex},
        proposal_block::ProposalBlockProofTarget,
    },
    sparse_merkle_tree::{
        gadgets::process::process_smt::SmtProcessProof, goldilocks_poseidon::WrappedHashOut,
    },
    transaction::{
        circuits::{
            MergeAndPurgeTransitionCircuit, MergeAndPurgeTransitionProofWithPublicInputs,
            MergeAndPurgeTransitionPublicInputsTarget,
        },
        gadgets::block_header::{get_block_hash_target, BlockHeaderTarget},
    },
    zkdsa::{
        account::Address,
        circuits::{
            SimpleSignatureCircuit, SimpleSignatureProofWithPublicInputs,
            SimpleSignaturePublicInputsTarget,
        },
        gadgets::account::AddressTarget,
    },
};

use super::{
    address_list::TransactionSenderWithValidity,
    gadgets::address_list::TransactionSenderWithValidityTarget,
};

// type C = PoseidonGoldilocksConfig;
// type H = <C as GenericConfig<D>>::InnerHasher;
// type F = <C as GenericConfig<D>>::F;
// const D: usize = 2;
const N_LOG_MAX_BLOCKS: usize = 32;

pub struct OneBlockProofTarget<
    const D: usize,
    const N_LOG_USERS: usize, // N_LOG_MAX_USERS
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_TXS: usize,
    const N_DEPOSITS: usize,
> {
    pub deposit_block_target:
        DepositBlockProofTarget<D, N_LOG_RECIPIENTS, N_LOG_CONTRACTS, N_LOG_VARIABLES, N_DEPOSITS>,
    pub proposal_block_target: ProposalBlockProofTarget<D, N_LOG_USERS, N_TXS>,
    pub approval_block_target: ApprovalBlockProofTarget<D, N_LOG_USERS, N_TXS>,
    pub user_tx_proofs: [RecursiveProofTarget<D>; N_TXS],
    pub received_signatures: [RecursiveProofTarget<D>; N_TXS],
    pub block_number: Target,
    pub prev_block_header_proof: MerkleProofTarget<N_LOG_MAX_BLOCKS>,
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
        default_user_tx_proofs: &MergeAndPurgeTransitionProofWithPublicInputs<F, C, D>,
        deposit_process_proofs: &[(SmtProcessProof<F>, SmtProcessProof<F>, SmtProcessProof<F>)],
        world_state_process_proofs: &[SmtProcessProof<F>],
        world_state_revert_proofs: &[SmtProcessProof<F>],
        received_signatures: &[Option<SimpleSignatureProofWithPublicInputs<F, C, D>>],
        default_simple_signature: &SimpleSignatureProofWithPublicInputs<F, C, D>,
        latest_account_tree_process_proofs: &[SmtProcessProof<F>],
        block_header_siblings: &[HashOut<F>],
        prev_block_hash: HashOut<F>,
        old_world_state_root: WrappedHashOut<F>,
        old_latest_account_root: WrappedHashOut<F>,
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        self.deposit_block_target
            .set_witness(pw, deposit_process_proofs);
        let (_transactions_digest, proposal_world_state_root) =
            self.proposal_block_target.set_witness(
                pw,
                world_state_process_proofs,
                &user_tx_proofs
                    .iter()
                    .cloned()
                    .map(|p| p.public_inputs)
                    .collect::<Vec<_>>(),
                old_world_state_root,
            );
        self.approval_block_target.set_witness(
            pw,
            block_number,
            world_state_revert_proofs,
            &user_tx_proofs
                .iter()
                .map(|p| p.public_inputs.clone())
                .collect::<Vec<_>>(),
            &received_signatures
                .iter()
                .cloned()
                .map(|p| p.map(|p| p.public_inputs))
                .collect::<Vec<_>>(),
            latest_account_tree_process_proofs,
            proposal_world_state_root,
            old_latest_account_root,
        );

        assert!(user_tx_proofs.len() <= self.user_tx_proofs.len());
        for (r_t, r) in self.user_tx_proofs.iter().zip(user_tx_proofs.iter()) {
            r_t.set_witness(pw, &ProofWithPublicInputs::from(r.clone()), true);
        }

        for r_t in self.user_tx_proofs.iter().skip(user_tx_proofs.len()) {
            r_t.set_witness(
                pw,
                &ProofWithPublicInputs::from(default_user_tx_proofs.clone()),
                false,
            );
        }

        assert!(received_signatures.len() <= self.received_signatures.len());
        for (r_t, r) in self
            .received_signatures
            .iter()
            .zip(received_signatures.iter())
        {
            let r: Option<&_> = r.into();
            r_t.set_witness(
                pw,
                &ProofWithPublicInputs::from(r.unwrap_or(default_simple_signature).clone()),
                r.is_some(),
            );
        }

        for r_t in self
            .received_signatures
            .iter()
            .skip(received_signatures.len())
        {
            r_t.set_witness(
                pw,
                &ProofWithPublicInputs::from(default_simple_signature.clone()),
                false,
            );
        }

        self.prev_block_header_proof.set_witness(
            pw,
            block_number as usize - 1,
            prev_block_hash.into(),
            &block_header_siblings
                .iter()
                .cloned()
                .map(|v| v.into())
                .collect::<Vec<_>>(),
        );

        pw.set_target(
            self.block_header.block_number,
            F::from_canonical_u32(block_number),
        );

        pw.set_hash_target(self.prev_block_hash, prev_block_hash);

        // let address_list = make_address_list(user_tx_proofs, received_signatures, N_TXS);

        // ProposalAndApprovalBlockPublicInputs {
        //     address_list,
        //     deposit_list: todo!(),
        //     old_account_tree_root: todo!(),
        //     new_account_tree_root: todo!(),
        //     old_world_state_root,
        //     new_world_state_root: todo!(),
        //     old_prev_block_header_digest: todo!(),
        //     new_prev_block_header_digest: todo!(),
        //     block_hash: todo!(),
        // }
    }
}

pub fn make_block_proof_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const N_LOG_MAX_USERS: usize,
    const N_LOG_MAX_TXS: usize,
    const N_LOG_MAX_CONTRACTS: usize,
    const N_LOG_MAX_VARIABLES: usize,
    const N_LOG_TXS: usize,
    const N_LOG_RECIPIENTS: usize,
    const N_LOG_CONTRACTS: usize,
    const N_LOG_VARIABLES: usize,
    const N_DIFFS: usize,
    const N_MERGES: usize,
    const N_TXS: usize,
    const N_DEPOSITS: usize,
>(
    merge_and_purge_circuit: &MergeAndPurgeTransitionCircuit<
        F,
        C,
        D,
        N_LOG_MAX_USERS,
        N_LOG_MAX_TXS,
        N_LOG_MAX_CONTRACTS,
        N_LOG_MAX_VARIABLES,
        N_LOG_TXS,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_DIFFS,
        N_MERGES,
    >,
    simple_signature_circuit: &SimpleSignatureCircuit<F, C, D>,
) -> ProposalAndApprovalBlockCircuit<
    F,
    C,
    D,
    N_LOG_MAX_USERS,
    N_LOG_TXS,
    N_LOG_RECIPIENTS,
    N_LOG_CONTRACTS,
    N_LOG_VARIABLES,
    N_TXS,
    N_DEPOSITS,
>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // builder.debug_gate_row = Some(22927);

    // deposit block
    let deposit_block_target: DepositBlockProofTarget<
        D,
        N_LOG_RECIPIENTS,
        N_LOG_CONTRACTS,
        N_LOG_VARIABLES,
        N_DEPOSITS,
    > = DepositBlockProofTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher>(&mut builder);

    // proposal block
    let proposal_block_target: ProposalBlockProofTarget<D, N_LOG_MAX_USERS, N_TXS> =
        ProposalBlockProofTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher>(
            &mut builder,
        );

    // approval block
    let approval_block_target: ApprovalBlockProofTarget<D, N_LOG_MAX_USERS, N_TXS> =
        ApprovalBlockProofTarget::add_virtual_to::<F, <C as GenericConfig<D>>::Hasher>(
            &mut builder,
        );

    let mut user_tx_proofs = vec![];
    for _ in 0..N_TXS {
        let b = RecursiveProofTarget::add_virtual_to(&mut builder, &merge_and_purge_circuit.data);
        user_tx_proofs.push(b);
    }

    for ((u, p), a) in user_tx_proofs
        .iter()
        .zip(proposal_block_target.user_transactions.iter())
        .zip(approval_block_target.user_transactions.iter())
    {
        let user_tx_public_inputs =
            MergeAndPurgeTransitionPublicInputsTarget::decode(&u.inner.0.public_inputs);
        MergeAndPurgeTransitionPublicInputsTarget::connect(&mut builder, p, &user_tx_public_inputs);
        MergeAndPurgeTransitionPublicInputsTarget::connect(&mut builder, a, &user_tx_public_inputs);
    }

    let mut received_signatures = vec![];
    for _ in 0..N_TXS {
        let b = RecursiveProofTarget::add_virtual_to(&mut builder, &simple_signature_circuit.data);
        received_signatures.push(b);
    }

    for (r, a) in received_signatures
        .iter()
        .zip(approval_block_target.received_signatures.iter())
    {
        let signature = SimpleSignaturePublicInputsTarget::decode(&r.inner.0.public_inputs);
        SimpleSignaturePublicInputsTarget::connect(&mut builder, &a.0, &signature);
    }

    assert_eq!(
        proposal_block_target.user_transactions.len(),
        approval_block_target.received_signatures.len()
    );
    for (user_tx_proof, received_signature) in proposal_block_target
        .user_transactions
        .iter()
        .zip(approval_block_target.received_signatures.iter())
    {
        // publish ID list
        // public_inputs[(5*i)..(5*i+5)]
        builder.register_public_inputs(&user_tx_proof.sender_address.elements); // sender_address
        builder.register_public_input(received_signature.1.target); // not_cancel_flag
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

    builder.register_public_inputs(&approval_block_target.old_latest_account_root.elements);
    builder.register_public_inputs(&approval_block_target.new_latest_account_root.elements);

    builder.register_public_inputs(&proposal_block_target.old_world_state_root.elements);
    builder.register_public_inputs(&proposal_block_target.new_world_state_root.elements);

    // block header
    let block_number = builder.add_virtual_target();
    builder.range_check(block_number, N_LOG_MAX_BLOCKS);
    let transactions_digest = proposal_block_target.transactions_digest;
    let deposit_digest = deposit_block_target.deposit_digest;
    let proposed_world_state_digest = proposal_block_target.new_world_state_root;
    let approved_world_state_digest = approval_block_target.new_world_state_root;
    let latest_account_digest = approval_block_target.new_latest_account_root;

    // `block_number - 1` までの block header で block header tree を作る.
    let prev_block_header_proof: MerkleProofTarget<N_LOG_MAX_BLOCKS> =
        MerkleProofTarget::add_virtual_to::<F, C::Hasher, D>(&mut builder);
    let prev_block_hash = builder.add_virtual_hash();
    let prev_block_header_digest = get_merkle_root_target::<F, C::Hasher, D>(
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
    let block_hash = get_block_hash_target::<F, C::Hasher, D>(&mut builder, &block_header);

    builder.register_public_inputs(&prev_block_header_proof.root.elements); // old_root
    builder.register_public_inputs(&prev_block_header_digest.elements); // new_root
    builder.register_public_inputs(&block_hash.elements);
    let block_circuit_data = builder.build::<C>();
    assert_eq!(
        block_circuit_data.prover_only.public_inputs.len(),
        5 * N_TXS + 13 * N_DEPOSITS + 28
    );

    let targets = OneBlockProofTarget {
        proposal_block_target,
        approval_block_target,
        deposit_block_target,
        user_tx_proofs: user_tx_proofs
            .try_into()
            .map_err(|_| "user_tx_proofs is too long")
            .unwrap(),
        received_signatures: received_signatures
            .try_into()
            .map_err(|_| "received_signatures is too long")
            .unwrap(),
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
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalAndApprovalBlockPublicInputs<F: RichField> {
    pub address_list: Vec<TransactionSenderWithValidity<F>>,
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
        for TransactionSenderWithValidity {
            sender_address,
            is_valid,
        } in self.address_list.clone()
        {
            public_inputs.append(&mut sender_address.0.elements.into());
            // public_inputs.push(last_block_number);
            public_inputs.push(F::from_bool(is_valid));
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
            public_inputs.append(&mut variable_index.to_hash_out().elements.into());
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
    pub address_list: [TransactionSenderWithValidityTarget; N_TXS],
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

pub fn parse_proposal_and_approval_public_inputs<const N_TXS: usize, const N_DEPOSITS: usize>(
    public_inputs_t: &[Target],
) -> ProposalAndApprovalBlockPublicInputsTarget<N_TXS, N_DEPOSITS> {
    let mut public_inputs_t = public_inputs_t.iter();
    let address_list = (0..N_TXS)
        .map(|_| TransactionSenderWithValidityTarget {
            sender_address: HashOutTarget {
                elements: [
                    *public_inputs_t.next().unwrap(),
                    *public_inputs_t.next().unwrap(),
                    *public_inputs_t.next().unwrap(),
                    *public_inputs_t.next().unwrap(),
                ],
            },
            // last_block_number: *public_inputs_t.next().unwrap(),
            is_valid: BoolTarget::new_unsafe(*public_inputs_t.next().unwrap()),
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
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
        const N_LOG_USERS: usize,
        const N_LOG_TXS: usize,
        const N_LOG_RECIPIENTS: usize,
        const N_LOG_CONTRACTS: usize,
        const N_LOG_VARIABLES: usize,
        const N_TXS: usize,
        const N_DEPOSITS: usize,
    >
    ProposalAndApprovalBlockCircuit<
        F,
        C,
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
            .map(|_| TransactionSenderWithValidity {
                sender_address: Address::read(&mut public_inputs),
                is_valid: public_inputs.next().unwrap().is_nonzero(),
            })
            .collect::<Vec<_>>();
        let deposit_list = (0..N_DEPOSITS)
            .map(|_| DepositInfo {
                receiver_address: Address::read(&mut public_inputs),
                contract_address: Address::read(&mut public_inputs),
                variable_index: VariableIndex::read(&mut public_inputs),
                amount: *public_inputs.next().unwrap(),
            })
            .collect::<Vec<_>>();
        let old_account_tree_root = *WrappedHashOut::read(&mut public_inputs);
        let new_account_tree_root = *WrappedHashOut::read(&mut public_inputs);

        let old_world_state_root = *WrappedHashOut::read(&mut public_inputs);
        let new_world_state_root = *WrappedHashOut::read(&mut public_inputs);
        let old_prev_block_header_digest = *WrappedHashOut::read(&mut public_inputs);
        let new_prev_block_header_digest = *WrappedHashOut::read(&mut public_inputs);
        let block_hash = *WrappedHashOut::read(&mut public_inputs);

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
        assert_eq!(public_inputs.len(), 5 * N_TXS + 13 * N_DEPOSITS + 28);

        self.data.verify(ProofWithPublicInputs {
            proof: proof_with_pis.proof,
            public_inputs,
        })
    }
}
