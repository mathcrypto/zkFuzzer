# zk Circom Fuzzer

CircomFuzzer is a dynamic testing tool specifically designed for Circom circuits used in zero-knowledge proof systems. It employs dynamic analysis techniques to identify security vulnerabilities and correctness issues in ZK circuits.

## Overview

CircomFuzzer uses a combination of mutation-based fuzzing and constraint analysis to detect common vulnerabilities in Circom circuits. It works by:

1. Compiling the target circuit to generate WASM and R1CS artifacts
2. Generating and mutating circuit inputs to create test cases
3. Executing the circuit with various inputs and comparing witness outputs
4. Analyzing R1CS constraints to identify under-constrained variables


## Key Differences from Static Analyzers

Unlike static analysis tools like Circomspect, CircomFuzzer:

- Executes the circuit with real inputs to find runtime vulnerabilities

- Verifies the actual behavior of the circuit through witness generation


## Analyzis of Security Vulnerabilities in zkVoting Circuits

### Vulnerability 1: Merkle Root Inconsistency

**Location:** VotingCircuit.circom

**Description:** The circuit accepts two separate representations of the Merkle root without verifying they match:
1. A dedicated `merkleRoot` input signal used for nullifier calculation
2. The root included in the `authPath` array at position `treeDepth + 1` used for Merkle proof verification

**Impact:** A malicious user could provide a valid authentication path with a legitimate Merkle root in `authPath[treeDepth + 1]` while supplying a different value for the `merkleRoot` input. This would allow the Merkle proof to verify successfully but generate an incorrect nullifier hash, potentially enabling double-voting.

**Fix:** Add a constraint to ensure consistency between the two root values:
```circom
merkleRoot === authPath[treeDepth + 1];
```

### Vulnerability 2: Under-constrained Nullifier Calculation

**Location:** VotingCircuit.circom

**Description:** The nullifier calculation only depends on two inputs:
```circom
nullifierPoseidon.inputs[0] <== merkleRoot;
nullifierPoseidon.inputs[1] <== authPath[0];
nullifierPoseidon.out === nullifierHash;
```

This creates a vulnerability as the `voterIndex` (position in the Merkle tree) is not included in the nullifier calculation.

**Impact:** Multiple voters with the same leaf value would produce identical nullifiers. A malicious user could claim to be at different indices within the Merkle tree while using the same leaf value, allowing them to vote multiple times without being detected by the nullifier mechanism.

**Fix:** Include the voter's position in the nullifier calculation:
```circom
nullifierPoseidon.inputs[0] <== merkleRoot;
nullifierPoseidon.inputs[1] <== authPath[0];
nullifierPoseidon.inputs[2] <== voterIndex;  // Add voter position
nullifierPoseidon.out === nullifierHash;
```

