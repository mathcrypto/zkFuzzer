const fs = require('fs');
const path = require('path');
const { execSync, exec } = require('child_process');
const crypto = require('crypto');
const R1CS = require('./R1CSParser');
const { error } = require('console');

/**
 * A general-purpose fuzzer for Circom circuits that targets common vulnerabilities
 * like under-constrained variables and unsafe reuse of subcircuits.
 */
class CircomFuzzer {
  constructor(circuitPath, options = {}) {
    this.circuitPath = circuitPath;
    this.circuitName = path.basename(circuitPath, '.circom');
    this.outputDir = options.outputDir || './build';
    this.iterations = options.iterations || 100;
    this.fieldSize = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    this.verbose = options.verbose || false;
    
    // Ensure output directory exists
    if (!fs.existsSync(this.outputDir)) {
      fs.mkdirSync(this.outputDir, { recursive: true });
    }
  }

  log(message, isVerbose = false) {
    if (!isVerbose || (isVerbose && this.verbose)) {
      console.log(message);
    }
  }

  /**
   * Compile the circuit to generate R1CS constraints and wasm
   */
  async compileCircuit() {
    this.log(`Compiling circuit: ${this.circuitPath}`);
    
    try {
      execSync(`circom ${this.circuitPath} --r1cs --wasm -o ${this.outputDir}`);
      this.log('Circuit compiled successfully');
      
      // Check if compilation was successful
      const wasmPath = path.join(this.outputDir, `${this.circuitName}_js/${this.circuitName}.wasm`);
      const r1csPath = path.join(this.outputDir, `${this.circuitName}.r1cs`);
      
      if (!fs.existsSync(wasmPath) || !fs.existsSync(r1csPath)) {
        throw new Error(`Circuit compilation failed: output files not found`);
      }
      
      return true;
    } catch (error) {
      console.error('Circuit compilation failed:', error.message);
      return false;
    }
  }

  /**
   * Generate random field element for input
   */
  generateRandomFieldElement() {
    // Generate a random BigInt in the range [0, fieldSize-1]
    const randomBytes = crypto.randomBytes(32);
    let randomBigInt = BigInt('0x' + randomBytes.toString('hex'));
    return (randomBigInt % this.fieldSize).toString();
  }

  
   // Generate structured input based on circuit input signals
   
  generateInput(inputTemplate) {
      return inputTemplate;

    }

// Generate multiple mutated inputs based on the input template
  generateMutatedInputs(inputTemplate, mutationCount = 10) {
    this.log(`Generating mutated inputs with improved strategy..`, true);
    const mutations = [];
    for (let i = 0; i < mutationCount; i++) {
      const mutatedInput = JSON.parse(JSON.stringify(inputTemplate));
      const keys = Object.keys(mutatedInput);

      if (keys.length === 0) {
        this.log('Empty input template. Skipping mutation.', true);
        continue;
      }
      const fieldsToMutate = Math.min(Math.floor(Math.random() * 3)+1, keys.length);

      for (let j = 0; j < fieldsToMutate; j++) {
        const randomKey = keys[Math.floor(Math.random() * keys.length)];

        if (Array.isArray(mutatedInput[randomKey])) {
          const arrayIndex = Math.floor(Math.random() * mutatedInput[randomKey].length);
          mutatedInput[randomKey][arrayIndex] = this.generateRandomFieldElement();
          this.log(`Mutated array input ${randomKey}[${arrayIndex}]`, true);
        } else {
          mutatedInput[randomKey] = this.generateRandomFieldElement();
          this.log(`Mutated scalar input ${randomKey}`, true);
        }
      }
      mutations.push(mutatedInput);
    }
    this.log(`Generated ${mutations.length} mutated inputs`, true);
    return mutations;
  }
  /**
   * Analyze circuit inputs by inspecting the circuit file and compiled artifacts
   */
  async analyzeCircuitInputs() {
    this.log('Analyzing circuit inputs...');
    
    try {
      const inputTemplate = {};
      
      // First try to analyze from the circuit source
      if (fs.existsSync(this.circuitPath)) {
        const circuitContent = fs.readFileSync(this.circuitPath, 'utf8');
        
        // Look for input signal declarations
        const inputRegex = /signal\s+input\s+(\w+)(?:\[(\d+)\])?/g;
        
        let match;
        while ((match = inputRegex.exec(circuitContent)) !== null) {
          const signalName = match[1];
          const arraySize = match[2];
          
          if (arraySize) {
            // This is an array input
            this.log(`Found array input: ${signalName}[${arraySize}]`, true);
            inputTemplate[signalName] = Array(parseInt(arraySize)).fill('0');
          } else {
            // This is a scalar input
            this.log(`Found scalar input: ${signalName}`, true);
            inputTemplate[signalName] = '0';
          }
        }
      }
      
      // Check if we found any inputs
      if (Object.keys(inputTemplate).length === 0) {
        this.log('Could not determine input structure from circuit source.');
        this.log('Please provide an input template.');
        return null;
      }
      
      return inputTemplate;
    } catch (error) {
      console.error('Error analyzing circuit inputs:', error.message);
      return null;
    }
  }
  generateVotingCircuitValidInput(inputTemplate) {
    const mutatedInput = JSON.parse(JSON.stringify(inputTemplate));
    
    // Decide what to mutate
    const mutationType = Math.floor(Math.random() * 2);
    
    // For testing purposes, we'll try to keep the output valid
    if (mutationType === 0) {
      // Just change voteChoice between 0 and 1
      mutatedInput.voteChoice = mutatedInput.voteChoice === "0" ? "1" : "0";
      
      // When we change voteChoice, we need to update voteCommitment
      // Since we don't have easy access to Poseidon here, we'll skip modifying voteCommitment
      // and trust that the circuit will tell us it's invalid, which is expected
    } 
    else {
      // Change randomness
      mutatedInput.randomness = this.generateRandomFieldElement();
      
      // Again, would need to update voteCommitment
    }
    
    return mutatedInput;
  }

  /**
   * Test for under-constrained variables by trying to create invalid proofs
   * This method tries to detect the "Assigned but Unconstrained" vulnerability
   * mentioned in the Tornado Cash MIMC hash bug example
   */
  
  async testForUnderconstrainedVariables(inputTemplate) {
    this.log('Testing for under-constrained variables...');
    
    try {
      // Generate random inputs based on the input template
      const validInput = this.generateInput(inputTemplate);
      
      // Write these inputs to a JSON file
      const inputPath = path.join(this.outputDir, 'input.json');
      fs.writeFileSync(inputPath, JSON.stringify(validInput, null, 2));
  
      // Generate witness using the compiled wasm file
      const wasmPath = path.join('../circuits', `${this.circuitName}.wasm`);
      const witCmd = path.join(this.outputDir, 'witness1.wtns');
  
      try {
        if (fs.existsSync(path.join('../circuits/witness', 'witness1.wtns'))) {
          this.log('Using existing witness file...', true);
          fs.copyFileSync(path.join('../circuits/witness', 'witness1.wtns'), witCmd);
        } else {
          // Generate a new witness
          this.log('Generating witness for valid input...');
          execSync(`snarkjs wtns calculate ${wasmPath} ${inputPath} ${witCmd}`);
          this.log('Witness generated successfully for valid input', true);
        }
        this.log('Valid inputs produce a valid witness - this is expected');
      } catch (error) {
        console.error('Error with valid witness:', error.message);
        return [{ error: 'witness_error', details: error.message }];
      }
  
      // Test for nullifier bypass
      const findings = [];
      this.log('Testing for nullifier bypass...', true);
      try {
        const modifiedInput = JSON.parse(JSON.stringify(validInput));
        if (modifiedInput.nullifierHash) {
          const originalHash = modifiedInput.nullifierHash;
          modifiedInput.nullifierHash = this.generateRandomFieldElement();
          this.log(`Testing nullifier bypass: changed from ${originalHash} to ${modifiedInput.nullifierHash}`, true);
          
          const modifiedInputPath = path.join(this.outputDir, 'nullifier-test-input.json');
          fs.writeFileSync(modifiedInputPath, JSON.stringify(modifiedInput, null, 2));
          
          const modifiedWitPath = path.join(this.outputDir, 'nullifier-test-witness.wtns');
          try {
            execSync(`snarkjs wtns calculate ${wasmPath} ${modifiedInputPath} ${modifiedWitPath}`);

            this.log('Circuit accepted an invalid nullifierHash value! This is a potential vulnerability.');
            
            findings.push({
              type: 'under-constrained-variable',
              severity: 'high',
              description: 'Circuit accepted an invalid nullifierHash value!',
              recommendation: 'Ensure nullifierHash is properly constrained in the circuit'
            });
          } catch (error) {
            this.log('Nullifier validation working correctly - circuit rejected invalid nullifierHash');
          }
        } else {
          this.log('No nullifierHash found in input - skipping nullifier bypass test', true);
        }
      } catch (error) {
        console.error('Error testing for nullifier bypass:', error.message);
      }
      
      if (findings.length > 0) {
        return findings;
      }
  
      // Test with mutated inputs
      this.log('Testing with mutated inputs...');
      const mutatedInputs = this.generateMutatedInputs(inputTemplate, 3);
      const mutationFindings = [];
      
      for (let i = 0; i < mutatedInputs.length; i++) {
        this.log(`Testing mutated input ${i+1} of ${mutatedInputs.length}...`);
        const mutatedInputPath = path.join(this.outputDir, `mutated-input-${i}.json`);
        fs.writeFileSync(mutatedInputPath, JSON.stringify(mutatedInputs[i], null, 2));
        
        const mutatedWitCmd = path.join(this.outputDir, `witness-mutated-${i}.wtns`);
        
        try {
          execSync(`snarkjs wtns calculate ${wasmPath} ${mutatedInputPath} ${mutatedWitCmd}`);
          this.log(`Witness generated for mutated input ${i+1}.`, true);
          
          // Compare the two witnesses
          const witness1 = fs.readFileSync(witCmd);
          const witness2 = fs.readFileSync(mutatedWitCmd);
          
          if (witness1.equals(witness2)) {
            this.log(`Mutation ${i+1} produce identical witness! This indicates unconstrained variables`);
            mutationFindings.push({
              type: 'under-constrained-variable',
              severity: 'high',
              description: `Mutation ${i+1} produced identical witness to valid input`,
              recommendation: 'Check for <-- vs <== usage in your Circom code'
            });
          } else {
            this.log(`Mutation ${i+1} produced different witness - this is expected`);
          }
        } catch (error) {
          console.error(`Mutation ${i+1} was rejected by the circuit - this is expected for invalid inputs`);
          this.log(`Reason : ${error.message.split('\n')[0]}`, true);

        }
      }
      
      if (mutationFindings.length > 0) {
        return mutationFindings;
      }

      this.log('No under-constrained variables detected');
      this.log('Running static analysis for additional checks...');
  
      // Export R1CS to JSON for static analysis
      const r1csJsonPath = path.join(this.outputDir, `${this.circuitName}.r1cs.json`);
      if (!fs.existsSync(r1csJsonPath)) {
        execSync(`snarkjs r1cs export json ${this.outputDir}/${this.circuitName}.r1cs ${r1csJsonPath}`);
      }
      
      return this.analyzeR1CSConstraints(r1csJsonPath);
    } catch (error) {
      console.error('Error testing for under-constrained variables:', error.message);
      return this.analyzeCircuitStatically();
    }
  }
  
  analyzeR1CSConstraints(r1csJsonPath) {
    this.log(`Analyzing R1CS constraints from: ${r1csJsonPath}`);
    
    try {
      // Directly read the JSON file
      const r1csData = JSON.parse(fs.readFileSync(r1csJsonPath, 'utf8'));
      
      // Basic validation
      if (!r1csData.constraints || !Array.isArray(r1csData.constraints)) {
        throw new Error('Invalid R1CS JSON structure');
      }
      
      // 2. Build a graph of signal dependencies
      const signalDependencies = new Map();
      
      r1csData.constraints.forEach((constraint, index) => {
        // Analyze each part of the constraint (l, r, o)
        ['l', 'r', 'o'].forEach(part => {
          if (!constraint[part] || !Array.isArray(constraint[part])) {
            this.log(`Invalid ${part} constraint at index ${index}`, true);
            return;
          }
          
          constraint[part].forEach(signal => {
            const signalName = signal.signal;
            if (!signalDependencies.has(signalName)) {
              signalDependencies.set(signalName, new Set());
            }
            signalDependencies.get(signalName).add(index);
          });
        });
      });
      
      // 3. Identify potential unconstrained signals
      const unconstrainedSignals = [];
      
      for (const [signal, constraints] of signalDependencies.entries()) {
        if (constraints.size === 0) {
          unconstrainedSignals.push({
            signal,
            type: 'potential-unconstrained-signal',
            severity: 'high',
            description: 'Signal may be assigned but not constrained',
            recommendation: 'Check for <-- vs <== usage in your Circom code'
          });
        }
      }
      
      return unconstrainedSignals;
    } catch (error) {
      console.error('Error analyzing R1CS constraints:', error.message);
      return [];
    }
  }
  /**
   * Perform static analysis of the circuit file to find potential issues
   */
  analyzeCircuitStatically() {
    this.log('Performing static analysis of circuit source...');
    
    try {
      if (!fs.existsSync(this.circuitPath)) {
        return [];
      }
      
      const circuitContent = fs.readFileSync(this.circuitPath, 'utf8');
      const findings = []; // Changed from moreefindings to findings
      
      // Look for potential under-constrained variables
      // Search for the <-- operator which only assigns but doesn't constrain
      const assignmentRegex = /(\w+)\s*<--\s*.*;/g;
      let match;
      while ((match = assignmentRegex.exec(circuitContent)) !== null) {
        const signalName = match[1];
        findings.push({
          type: 'potential-unconstrained-signal',
          severity: 'high',
          signal: signalName,
          description: `Signal '${signalName}' is assigned with <-- but may not be constrained`,
          recommendation: 'Consider using <== instead of <-- to ensure constraints are properly enforced'
        });
      }
      
      return findings;
    } catch (error) {
      console.error('Error in static analysis:', error.message);
      return [];
    }
  }
  
  /**
   * Test for unsafe reuse of subcircuits
   * Looks for the pattern shown in the BigLessThan vulnerability example
   */
  async testForUnsafeReuse() {
    this.log('Testing for unsafe reuse of subcircuits...');
    
    try {
      if (!fs.existsSync(this.circuitPath)) {
        return [];
      }
      
      const circuitContent = fs.readFileSync(this.circuitPath, 'utf8');
      
      // Look for component instantiations and their outputs
      const componentRegex = /component\s+(\w+)\s*=\s*(\w+)/g;
      const signalAssignments = /(\w+)\.(\w+)\s*<?==\s*.*?;/g;
      
      const components = new Map();
      const usedOutputs = new Set();
      
      // Find all component instantiations
      let match;
      while ((match = componentRegex.exec(circuitContent)) !== null) {
        const componentName = match[1];
        const componentType = match[2];
        components.set(componentName, componentType);
      }
      
      // Find all signal assignments
      while ((match = signalAssignments.exec(circuitContent)) !== null) {
        const componentName = match[1];
        const signalName = match[2];
        
        // If this is accessing a component output
        if (components.has(componentName) && signalName === 'out') {
          usedOutputs.add(`${componentName}.out`);
        }
      }
      
      // Find components whose outputs might not be properly constrained
      const potentialIssues = [];
      for (const [componentName, componentType] of components.entries()) {
        if (!usedOutputs.has(`${componentName}.out`)) {
          potentialIssues.push({
            component: componentName,
            type: componentType
          });
        }
      }
      
      if (potentialIssues.length > 0) {
        return [{
          type: 'potential-unsafe-reuse',
          severity: 'high',
          description: 'Subcircuit outputs may not be properly constrained',
          recommendation: 'Ensure all component outputs are properly constrained with <== or ===',
          components: potentialIssues
        }];
      }
      
      return [];
    } catch (error) {
      console.error('Error testing for unsafe reuse:', error.message);
      return [];
    }
  }

  /**
   * Test for over-constrained circuits
   * These can lead to valid proofs being rejected
   */
  async testForOverconstrainedCircuits() {
    this.log('Testing for over-constrained circuits...');
    
    // This is a placeholder implementation
    return [];
  }

  /**
   * Test for computational logic errors
   */
  async testForComputationalErrors() {
    this.log('Testing for computational logic errors...');
    
    // This is a placeholder implementation
    return [];
  }

  /**
   * Run all fuzzing tests against the circuit
   */
  async runAllTests(inputTemplate) {
    if (!await this.compileCircuit()) {
      console.error('Cannot proceed with tests due to compilation failure');
      return [];
    }
    
    // Determine input structure if not provided
    if (!inputTemplate) {
      inputTemplate = await this.analyzeCircuitInputs();
      if (!inputTemplate) {
        console.error('Cannot proceed without a valid input template');
        return [];
      }
    }
    
    const vulnerabilities = [];
    
    // Test for under-constrained variables
    try {
      const underconstrainedVulns = await this.testForUnderconstrainedVariables(inputTemplate);
      vulnerabilities.push(...underconstrainedVulns);
    } catch (error) {
      console.error('Error in under-constrained variables test:', error.message);
    }
    
    // Test for unsafe reuse of subcircuits
    try {
      const unsafeReuseVulns = await this.testForUnsafeReuse();
      vulnerabilities.push(...unsafeReuseVulns);
    } catch (error) {
      console.error('Error in unsafe reuse test:', error.message);
    }
    
    // Test for over-constrained circuits
    try {
      const overconstrainedVulns = await this.testForOverconstrainedCircuits();
      vulnerabilities.push(...overconstrainedVulns);
    } catch (error) {
      console.error('Error in over-constrained circuits test:', error.message);
    }
    
    // Test for computational errors
    try {
      const computationalErrorVulns = await this.testForComputationalErrors();
      vulnerabilities.push(...computationalErrorVulns);
    } catch (error) {
      console.error('Error in computational errors test:', error.message);
    }
    
    // Report findings
    if (vulnerabilities.length > 0) {
      this.log('\n Potential vulnerabilities found:');
      vulnerabilities.forEach((vuln, i) => {
        this.log(`\n${i+1}. Type: ${vuln.type}`);
        this.log(`   Description: ${vuln.description}`);
        this.log(`   Recommendation: ${vuln.recommendation}`);
        
        if (vuln.components) {
          this.log('   Affected components:');
          vuln.components.forEach(comp => {
            this.log(`   - ${comp.component} (${comp.type})`);
          });
        }
      });
    } else {
      this.log('\n No potential vulnerabilities detected');
    }
    
    return vulnerabilities;
  }
}


module.exports = CircomFuzzer;

