# Coding Rules

- Generally follow the plonky2 conventions
- Tests should be written within the module
- Ensure that there are no warnings or errors when committing
- Target structures should implement make_constraints and set_witness
- In set_witness, call the non-Target version of the structure's calculation and perform validation
- Circuits that have the potential to generate proofs should be called as a library from other circuits and referred to as circuit, while circuits that do not generate proofs themselves but are used by other circuits should be referred to as gadget.
