use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        ext_target::ExtensionTarget,
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Debug)]
struct InverseOrZeroGeneratorExtension<const D: usize> {
    denominator: ExtensionTarget<D>,
    inverse: ExtensionTarget<D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F>
    for InverseOrZeroGeneratorExtension<D>
{
    fn dependencies(&self) -> Vec<Target> {
        self.denominator.to_target_array().to_vec()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let dem = witness.get_extension_target(self.denominator);
        let zero = F::Extension::ZERO;
        let one = F::Extension::ONE;
        let inverse = if !dem.is_zero() { one / dem } else { zero };
        out_buffer.set_extension_target(self.inverse, inverse)
    }
}

pub fn is_non_zero<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target: HashOutTarget,
) {
    let zero = builder.zero_extension();
    let one = builder.one_extension();
    let is_zeros = target
        .elements
        .into_iter()
        .map(|e| {
            let y = builder.convert_to_ext(e);
            let inv = builder.add_virtual_extension_target();
            builder.add_simple_generator(InverseOrZeroGeneratorExtension {
                denominator: y,
                inverse: inv,
            });

            // Enforce that y times some number equals 0 or 1.
            // not_y_times_inv = 1 - y * inv
            let not_y_times_inv = builder.arithmetic_extension(F::NEG_ONE, F::ONE, y, inv, one);
            let z = builder.mul_sub_extension(not_y_times_inv, not_y_times_inv, not_y_times_inv);
            builder.connect_extension(z, zero);

            // Return 0 only if e != 0.
            not_y_times_inv
        })
        .collect::<Vec<_>>();

    // Enforce some of target.elements is non-zero.
    let tmp0 = builder.mul_extension(is_zeros[0], is_zeros[1]);
    let tmp1 = builder.mul_extension(is_zeros[2], is_zeros[3]);
    let tmp2 = builder.mul_extension(tmp0, tmp1);
    builder.connect_extension(tmp2, zero);
}
