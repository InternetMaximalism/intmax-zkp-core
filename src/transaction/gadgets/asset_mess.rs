use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{transaction::asset::Transaction, zkdsa::gadgets::account::AddressTarget};

use super::utils::is_non_zero;

#[derive(Copy, Clone, Debug)]
pub struct TransactionTarget {
    pub to: AddressTarget,
    pub contract_address: AddressTarget,
    pub variable_index: HashOutTarget,
    pub amount: Target,
}

impl TransactionTarget {
    pub fn make_constraints<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            to: AddressTarget::new(builder),
            contract_address: AddressTarget::new(builder),
            variable_index: builder.add_virtual_hash(),
            amount: builder.add_virtual_target(),
        }
    }

    pub fn constant_default<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            to: AddressTarget::constant_default(builder),
            contract_address: AddressTarget::constant_default(builder),
            variable_index: builder.constant_hash(HashOut::ZERO),
            amount: builder.constant(F::ZERO),
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, value: Transaction<F>) {
        self.to.set_witness(pw, value.to);
        self.contract_address
            .set_witness(pw, value.kind.contract_address);
        pw.set_hash_target(self.variable_index, value.kind.variable_index.to_hash_out());
        pw.set_target(self.amount, F::from_canonical_u64(value.amount));
    }

    pub fn encode(&self) -> Vec<Target> {
        [
            vec![self.to.0, self.contract_address.0],
            self.variable_index.elements.to_vec(),
            vec![self.amount],
        ]
        .concat()
    }

    pub fn read(inputs: &mut core::slice::Iter<Target>) -> Self {
        Self {
            to: AddressTarget::read(inputs),
            contract_address: AddressTarget::read(inputs),
            variable_index: HashOutTarget {
                elements: [
                    *inputs.next().unwrap(),
                    *inputs.next().unwrap(),
                    *inputs.next().unwrap(),
                    *inputs.next().unwrap(),
                ],
            },
            amount: *inputs.next().unwrap(),
        }
    }
}
/// asset の組み合わせから一意に定まる hash を作成する.
///
/// NOTICE: mess はもとの asset を難読化する目的で用いてはならない.
///  例えば, 1 種類の NFT を mess にすると, その asset_id がそのまま現れるため容易に推測される.
pub fn assets_into_mess<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    assets_t: &[TransactionTarget],
) -> (HashOutTarget, Target) {
    let mut total_amount_t = builder.zero();
    let mut mess_t = HashOutTarget {
        elements: [builder.zero(); 4],
    };
    for target in assets_t {
        // total_inputs_t += a_t
        total_amount_t = builder.add(target.amount, total_amount_t);

        let asset_id_t =
            calc_asset_id::<F, H, D>(builder, target.contract_address.0, target.variable_index);
        for i in 0..3 {
            // mess_t.elements[i] += asset_id_t.elements[i] * amount_t
            mess_t.elements[i] =
                builder.mul_add(asset_id_t.elements[i], target.amount, mess_t.elements[i]);
        }
    }

    (mess_t, total_amount_t)
}

/// asset_id = PoseidonHash::two_to_one(contract_address, token_id)
/// ただし, asset_id は 0 でないとする.
fn calc_asset_id<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    contract_t: Target,
    token_id_t: HashOutTarget,
) -> HashOutTarget {
    let zero_t = builder.zero();
    let one_t = builder.one();

    let inputs = vec![
        contract_t,
        zero_t,
        zero_t,
        zero_t,
        token_id_t.elements[0],
        token_id_t.elements[1],
        token_id_t.elements[2],
        token_id_t.elements[3],
        one_t,
        zero_t,
        zero_t,
        one_t,
    ];

    let asset_id_t = builder.hash_n_to_hash_no_pad::<H>(inputs);
    is_non_zero(builder, asset_id_t);

    asset_id_t
}

/// inputs に含まれる各 asset の総量と, outputs に含まれる各 asset の総量が等しいことを検証する.
/// 本当は asset の種類ごとに分けて総和を計算するべき処理ではあるが,
/// ここでは各 asset の量に疑似乱数を乗算して総和を取ることにより,
/// 実際は一致していないのに一致していると判定する確率は限りなく 0 に近いことのみを保証する.
/// 偽造するためには未知の `asset_id` に対応する `contract_address` と `token_id` の組を求める必要がある.
///
/// NOTICE: `total_amount_t` を計算する時に overflow をチェックしないので,
///  `input_assets_t` や `output_assets_t` に含まれる各 asset の amount が
///  一定値 (例えば 2^56) 未満であることを事前に検証すると, より安全である.
pub fn verify_equal_assets<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_assets_t: &[TransactionTarget],
    output_assets_t: &[TransactionTarget],
) {
    let (input_mess_t, total_inputs_t) = assets_into_mess::<F, H, D>(builder, input_assets_t);
    let (output_mess_t, total_outputs_t) = assets_into_mess::<F, H, D>(builder, output_assets_t);
    builder.connect(total_inputs_t, total_outputs_t);
    builder.connect_hashes(input_mess_t, output_mess_t);
}
