# zk Circom Fuzzer
## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Running the Fuzzer](#running-the-fuzzer)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [About the Example Circuit](#about-the-example-circuit)
  - [Preparing Your Circuit](#preparing-your-circuit)
  - [Testing Your Circuit](#testing-your-circuit)
- [Case Study: Security Vulnerabilities in the zkVoting Circuit](#case-study-security-vulnerabilities-in-zkvoting-circuits)
  - [Automated Findings](#automated-findings)
  - [Manual Analysis](#manual-analysis)
  - [Connection Between Fuzzing and Manual Analysis](#connection-between-fuzzing-and-manual-analysis)

## Overview

CircomFuzzer is a comprehensive security testing tool for Circom circuits that combines dynamic execution testing and constraint analysis to detect vulnerabilities in zero-knowledge circuits. It works by:

1. Compiling the target circuit to generate WASM and R1CS artifacts
2. Generating both valid and mutated inputs to create diverse test cases:
   * Whether invalid inputs are properly rejected.
   * Whether valid inputs produce expected witnesses.
3. Performing graph-based analysis of R1CS constraints to identify structural weaknesses
4. Specifically targeting common ZK circuit vulnerabilities like unconstrained variables and unsafe component reuse

## Key features
* **Dynamic Testing**: Tests circuit behavior with valid and invalid inputs to verify.
* **Constraint Graph Analysis**: Maps relationships between signals to detect disconnected components.
* **Signal Usage Analysis**: Identifies signals that appear only once in constraints, suggesting potential vulnerabilities.

**Key Differences from Static Analyzers** 

Unlike static analysis tools like Circomspect, CircomFuzzer:

- Executes the circuit with real inputs to find runtime vulnerabilities

- Verifies the actual behavior of the circuit through witness generation
- Combines both dynamic testing and static analysis for more comprehensive results.

## Running the Fuzzer

### Prerequisities
- Node.js (v14 or higher)
- Circom (v2.0 or higher)
- snarkjs (latest version)

### Installation
1. Clone the repository:
```
git clone https://github.com/mathcrypto/zkFuzzer.git
cd zkFuzzer
```
2. Install dependencies:
```
npm install
```
3. Make the CLI fuzzer executable:
```
chmod +x fuzzer/cli-fuzzer.js
```
The CLI fuzzer is a command-line interface tool for security testing zero-knowledge proof circuits written in Circom. It works together with the circom-fuzzer.js module, which provides the core fuzzing functionality.


### About the Example Circuit

For this example, we're using a voting circuit from the ZeroKnowledgeVoting project:
- Source: https://github.com/zkPikachu/ZeroKnowledgeVoting/blob/main/circuit/circuit.circom
- Circuit type: Anonymous voting mechanism using zero-knowledge proofs
- Purpose: Enables voters to cast ballots while preserving privacy and preventing double voting



### Preparing your Circuit
Before running the fuzzer, you'll need a compiled circuit. You can use the included Makefile to prepare your circuit:
1. Compile the circuit 
```
make compile
```

This will:

 * Create a build directory if it doesn't exist.
 * Compile the Circom circuit to generate R1CS constraints and WASM
 * Place compilation outputs in the build directory.



For your convenience, the environment has already been partially prepared:
  *  The circuit is available at "circuits/VotingCircuit.circom"
  * A build folder has been created.
  * A valid input file has been provided for testing at "build/input.json".


For better vulnerability reports with human-readable signal names:
Generate symbol files:
```

circom circuits/VotingCircuit.circom --sym --output build
```


### Testing Your Circuit
Simply run the fuzzer with:
```
cd fuzzer
./cli-fuzzer.js ../circuits/VotingCircuit.circom build/input.json
```
### Using npm Scripts

This project includes several npm scripts to make running the fuzzer more convenient:

```bash
# Run the main fuzzer (requires circuit path and input file)
npm run fuzz -- ../circuits/VotingCircuit.circom build/input.json

# Run the specialized nullifier vulnerability test
npm test
```
The ```package.json``` file includes all necessary dependencies for the fuzzer, including circom, snarkjs, and other supporting libraries which are automatically installed during the installation step.
## Case Study: Security Vulnerabilities in the zkVoting Circuit

### Automated Findings
The fuzzer produces a detailed report highlighting potential vulnerabilities in your circuit:
1. **Disconnected Constraint Graph** (high severity):
   - 24 disconnected components were identified
   - This means parts of the circuit are logically isolated from each other
   - This could indicate missing constraints between related variables

2. **Potentially Unconstrained Signals** (high severity):
   - Three critical signals (`randomness`, `nullifierHash`, and `voteChoice`) are each only used once in constraints
   - When signals appear only once, they may not be properly constrained by the circuit logic
   - This could allow an attacker to manipulate these values without affecting proof validity

3. **Potential Unsafe Reuse** (high severity):
   - The `merkleProof` component isn't properly constrained
   - Component outputs should be constrained with `<==` or `===` operators
   - Without proper constraints, the Merkle proof verification might be bypassed


### Manual Analysis
Our code review of the VotingCircuit identified two critical vulnerabilities that might not be immediately obvious from automated testing alone:

#### Vulnerability 1: Merkle Root Inconsistency

**Description:** The circuit accepts two separate representations of the Merkle root without verifying they match:
1. A dedicated `merkleRoot` input signal used for nullifier calculation
2. The root included in the `authPath` array at position `treeDepth + 1` used for Merkle proof verification

**Impact:** A malicious user could provide a valid authentication path with a legitimate Merkle root in `authPath[treeDepth + 1]` while supplying a different value for the `merkleRoot` input. This would allow the Merkle proof to verify successfully but generate an incorrect nullifier hash, potentially enabling double-voting.

**Fix:** Add a constraint to ensure consistency between the two root values:
```bash
merkleRoot === authPath[treeDepth + 1];
```

#### Vulnerability 2: Under-constrained Nullifier Calculation

**Description:** The nullifier calculation only depends on two inputs:
```bash
nullifierPoseidon.inputs[0] <== merkleRoot;
nullifierPoseidon.inputs[1] <== authPath[0];
nullifierPoseidon.out === nullifierHash;
```

This creates a vulnerability as the `voterIndex` (position in the Merkle tree) is not included in the nullifier calculation.

**Impact:** Multiple voters with the same leaf value would produce identical nullifiers. A malicious user could claim to be at different indices within the Merkle tree while using the same leaf value, allowing them to vote multiple times without being detected by the nullifier mechanism.

**Fix:** Include the voter's position in the nullifier calculation:
```bash
nullifierPoseidon.inputs[0] <== merkleRoot;
nullifierPoseidon.inputs[1] <== authPath[0];
nullifierPoseidon.inputs[2] <== voterIndex;  // Add voter position
nullifierPoseidon.out === nullifierHash;
```

To specifically target and verify these vulnerabilities, we developed a specialized fuzzer extension: ```fuzzer/nullifier-fuzzer.js```

To run it:

```bash
cd fuzzer
node nullifier-fuzzer.js
```
### Connection Between Fuzzing and Manual Analysis
The fuzzer successfully identified two critical vulnerabilities in the zkVoting circuit:

1. Merkle Root Inconsistency:

- Detected through "disconnected constraint graph" and "unsafe reuse of merkleProof component" findings
- Correctly identified that two separate Merkle root representations weren't properly constrained to be equal


2. Under-constrained Nullifier Calculation:

- Detected through "Signal nullifierHash is only used once in constraints" finding
- Accurately flagged that the nullifier calculation was insufficient, missing critical inputs like voterIndex