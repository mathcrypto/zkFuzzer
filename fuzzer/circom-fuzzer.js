const fs = require('fs');
const path = require('path');
const { execSync} = require('child_process');
const crypto = require('crypto');
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
    this.log(`Compiling circuit: ${this.circuitName}`);
    
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

      this.log('Dynamic testing complete: No under-constrained variables detected');
      this.log('Running static analysis for additional checks...');
  
      // Export R1CS to JSON for static analysis
      const r1csJsonPath = path.join(this.outputDir, `${this.circuitName}.r1cs.json`);
      if (!fs.existsSync(r1csJsonPath)) {
        execSync(`snarkjs r1cs export json ${this.outputDir}/${this.circuitName}.r1cs ${r1csJsonPath}`);
      }

      const basicFindings = await this.analyzeR1CSConstraints(r1csJsonPath);
      
     // Ensure basicFindings is an array before attempting to spread it
if (Array.isArray(basicFindings)) {
  return basicFindings;

  return [...otherFindings, ...basicFindings];
} else {
  this.log('Warning: R1CS analysis did not return an array of findings');
  return otherFindings || [];
}
    } catch (error) {
      console.error('Error testing for under-constrained variables:', error.message);
      return this.analyzeCircuitStatically();
    }
  }
  
  /**
 * Improved R1CS constraint parser that correctly handles the snarkjs export format
 */
  async analyzeR1CSConstraints(r1csJsonPath) {
    this.log(`Analyzing R1CS constraints from: ${r1csJsonPath}`);
    
    try {
      // Check if file exists and read it
      if (!fs.existsSync(r1csJsonPath)) {
        this.log(`ERROR: R1CS JSON file not found at ${r1csJsonPath}`);
        return [];
      }
      
      const fileContent = fs.readFileSync(r1csJsonPath, 'utf8');
      
      // Parse JSON
      const r1csData = JSON.parse(fileContent);
      this.log(`Successfully parsed JSON data`);
      
      // Create a signal name mapping
      const signalNameMap = this.createSignalNameMapping(r1csData);
      
      // Validate structure
      if (!r1csData.constraints || !Array.isArray(r1csData.constraints)) {
        this.log('Invalid R1CS JSON structure: missing constraints array');
        return [];
      }
            
      // The constraint format is different from what we expected
      // Each constraint is an array of 3 objects [L, R, O] where:
      // - L represents the left side of the equation
      // - R represents the right side of the equation
      // - O represents the output
      // Each part is an object with signal IDs as keys and coefficients as values
      
      // Log sample constraint structure
      if (r1csData.constraints.length > 0) {
        this.log('First constraint structure:', true);
        this.log(JSON.stringify(r1csData.constraints[0], null, 2), true);
      }
      
      // Build the constraint graph with the correct format
      const constraintGraph = new Map();
      const signalDependencies = new Map();
      let validConstraintCount = 0;
      
      r1csData.constraints.forEach((constraint, index) => {
        if (!Array.isArray(constraint) || constraint.length !== 3) {
          this.log(`Invalid constraint format at index ${index}`, true);
          return;
        }
        
        // Each constraint is [L, R, O]
        const leftSide = constraint[0];   // L
        const rightSide = constraint[1];  // R
        const outputSide = constraint[2]; // O
        
        // Get signal IDs from each side
        const inputSignals = new Set();
        
        // Process left side signals
        for (const signalId in leftSide) {
          if (signalId !== '0') { // Skip constant term
            inputSignals.add(signalId);
            
            // Track signal dependencies
            if (!signalDependencies.has(signalId)) {
              signalDependencies.set(signalId, 0);
            }
            signalDependencies.set(signalId, signalDependencies.get(signalId) + 1);
          }
        }
        
        // Process right side signals
        for (const signalId in rightSide) {
          if (signalId !== '0') { // Skip constant term
            inputSignals.add(signalId);
            
            // Track signal dependencies
            if (!signalDependencies.has(signalId)) {
              signalDependencies.set(signalId, 0);
            }
            signalDependencies.set(signalId, signalDependencies.get(signalId) + 1);
          }
        }
        
        // Process output signals
        const outputSignals = new Set();
        for (const signalId in outputSide) {
          if (signalId !== '0') { // Skip constant term
            outputSignals.add(signalId);
            
            // Track signal dependencies
            if (!signalDependencies.has(signalId)) {
              signalDependencies.set(signalId, 0);
            }
            signalDependencies.set(signalId, signalDependencies.get(signalId) + 1);
          }
        }
        
        // Add edges to the graph
        inputSignals.forEach(input => {
          if (!constraintGraph.has(input)) {
            constraintGraph.set(input, new Set());
          }
          
          outputSignals.forEach(output => {
            constraintGraph.get(input).add(output);
            
            // Log with signal names if available
            const inputName = this.getSignalName(input, signalNameMap);
            const outputName = this.getSignalName(output, signalNameMap);
            this.log(`Added edge: ${inputName} -> ${outputName}`, true);
          });
        });
        
        validConstraintCount++;
      });
      
     
      
      // Print a sample of the graph with signal names
      let nodeCount = 0;
      for (const [node, edges] of constraintGraph.entries()) {
        if (nodeCount < 5) {
          const nodeName = this.getSignalName(node, signalNameMap);
          const edgeNames = Array.from(edges).map(edge => this.getSignalName(edge, signalNameMap));
          this.log(`Node ${nodeName} connects to: ${edgeNames.join(', ')}`, true);
        }
        nodeCount++;
      }
      
      // Find connected components
      const connectedComponents = this.findConnectedComponents(constraintGraph);
      
      
      // Log sizes of components with sample signal names
      connectedComponents.forEach((component, idx) => {
        this.log(`Component ${idx+1} has ${component.length} signals`, true);
        if (component.length > 0 && component.length <= 10) {
          // For small components, log all signal names
          const signalNames = component.map(signal => this.getSignalName(signal, signalNameMap));
          this.log(`  Signal names: ${signalNames.join(', ')}`, true);
        } else if (component.length > 10) {
          // For larger components, log a sample
          const sampleSignals = component.slice(0, 5);
          const signalNames = sampleSignals.map(signal => this.getSignalName(signal, signalNameMap));
          this.log(`  Sample signal names: ${signalNames.join(', ')}...`, true);
        }
      });
      
      // Identify potential issues
      const findings = [];
      
      // Check for leaf signals (signals with no outgoing edges)
      for (const [signal, outgoingEdges] of constraintGraph.entries()) {
        if (outgoingEdges.size === 0) {
          const signalName = this.getSignalName(signal, signalNameMap);
          findings.push({
            type: 'potential-leaf-signal',
            severity: 'medium',
            signal: signal,
            signalName: signalName,
            description: `Signal ${signalName} doesn't affect any other signals`,
            recommendation: 'Verify that this signal is properly constrained'
          });
        }
      }
      
      // Check for disconnected components
      if (connectedComponents.length > 1) {
        // Get signal names for each component
        const componentSummary = connectedComponents.map((component, idx) => {
          return {
            id: idx +1,
            size: component.length,
            sampleSignals: component.length > 0 && component.length <= 5
              ? component.map(signal => this.getSignalName(signal, signalNameMap)).join(', ')
              : `${Math.min(3, component.length)} signal samples`
          };
          });
          findings.push({
            type: 'disconnected-constraint-graph',
            severity: 'high',
            description: `Found ${connectedComponents.length} disconnected components`,
            recommendation: 'Ensure all signals are properly connected in the circuit',
            componentSummary
          });
        }
          
      
      // Check for signals used only once
      for (const [signal, count] of signalDependencies.entries()) {
        if (count === 1) {
          const signalName = this.getSignalName(signal, signalNameMap);
          findings.push({
            type: 'potential-unconstrained-signal',
            severity: 'high',
            signal: signal,
            signalName: signalName,
            description: `Signal ${signalName} is only used once in constraints`,
            recommendation: 'Verify that this signal is properly constrained'
          });
        }
      }
      
      this.log(`Analysis complete, found ${findings.length} potential issues`);

      return findings;
    } catch (error) {
      console.error('Error analyzing R1CS constraints:', error.message);
      console.error(error.stack);
      return [];
    }
  }
  
  /**
   * Create a mapping from signal IDs to meaningful names
   */
  createSignalNameMapping(r1csData) {
    const signalNameMap = new Map();
    
    // Add special signal - constant 1
    signalNameMap.set('0', 'one');
    
    // Add mappings based on circuit info
    if (r1csData.nVars && r1csData.nPubInputs && r1csData.nOutputs) {
      const nPubInputs = r1csData.nPubInputs;
      const nOutputs = r1csData.nOutputs;
      
      // Map public inputs
      for (let i = 1; i <= nPubInputs; i++) {
        signalNameMap.set(String(i), `public_input_${i}`);
      }
      
      // Map outputs - this is an approximation, might need adjustment
      let outputStart = nPubInputs + 1;
      for (let i = 0; i < nOutputs; i++) {
        signalNameMap.set(String(outputStart + i), `output_${i+1}`);
      }
    }
    
    // Add circuit-specific mappings - customize these based on your voting circuit
    if (this.circuitName.toLowerCase().includes('voting')) {
      // Common signals in voting circuits - adjust IDs based on your circuit
      const votingCircuitMappings = {
        '2': 'voteChoice',
        '3': 'randomness',
        '16': 'nullifierHash',
        '17': 'merkleRoot',
        '18': 'pathIndices',
        '19': 'merkleRoot',
        '98': 'intermediateHash',
        '99': 'commitment',
        '100': 'intermediateHash2',
        '101': 'commitment2'
      };
      
      // Add these mappings
      Object.entries(votingCircuitMappings).forEach(([id, name]) => {
        signalNameMap.set(id, name);
      });
    }
    
    return signalNameMap;
  }
  
  /**
   * Get the human-readable name for a signal ID
   */
  getSignalName(signalId, signalNameMap) {
    if (signalNameMap && signalNameMap.has(signalId)) {
      return signalNameMap.get(signalId);
    }
    return `signal_${signalId}`;
  }
  
  /**
   * Update the findConnectedComponents method to use signal names in logging
   */
  findConnectedComponents(graph) {
    
    // Rest of your existing method...
    const visited = new Set();
    const components = [];
    
    for (const node of graph.keys()) {
      if (!visited.has(node)) {
        const component = new Set();
        this.depthFirstSearch(graph, node, visited, component);
        components.push(Array.from(component));
        
      }
    }
    
   
    return components;
  }
  async extractSignalNames(inputTemplate) {
    // Load the witness calculator
    const wasmPath = path.join('../circuits', `${this.circuitName}.wasm`);
    const wasmBuffer = fs.readFileSync(wasmPath);
    const wc = await require('./witness_calculator.js')(wasmBuffer);
    
    // Common signal names in voting circuits
    const commonSignals = [
      'voteChoice', 'randomness', 'nullifierHash', 'root', 
      'merkleProof.root', 'commitment', 'voteCommitment',
      'main.voteChoice', 'main.randomness', 'main.nullifierHash'
    ];
    
    // Probe the circuit for these signal names
    const foundSignals = await wc.probeCommonSignalNames(commonSignals);
    
    // Create signal mappings
    const signalNameMap = new Map();
    
    // Add the found signals to the map
    foundSignals.forEach((info, name) => {
      // Here we would map from R1CS signal ID to the actual signal name
      // This part is tricky and may require circuit-specific knowledge
      signalNameMap.set(name, info);
    });
    
    return signalNameMap;
  }

 

// Helper function to perform depth-first search on the constraint graph
depthFirstSearch(graph, node, visited, component) {
  visited.add(node);
  component.add(node);
  
  const neighbors = graph.get(node) || new Set();
  if (this.verbose) {
    this.log(`  Visiting node ${node}, has ${neighbors.size} neighbors`);
  }
  
  for (const neighbor of neighbors) {
    if (!visited.has(neighbor)) {
      this.depthFirstSearch(graph, neighbor, visited, component);
    }
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
      this.log('Testing for under-constrained variables...');
      const underconstrainedVulns = await this.testForUnderconstrainedVariables(inputTemplate);
      this.log(`Found ${underconstrainedVulns.length} potential under-constrained variables`, true);
      vulnerabilities.push(...underconstrainedVulns);
    } catch (error) {
      console.error('Error in under-constrained variables test:', error.message);
    }
    
    // Test for unsafe reuse of subcircuits
    try {
      this.log('Testing for unsafe reuse of subcircuits...');
      const unsafeReuseVulns = await this.testForUnsafeReuse();
      this.log(`Found ${unsafeReuseVulns.length} potential unsafe reuse of subcircuits`, true);
      vulnerabilities.push(...unsafeReuseVulns);
    } catch (error) {
      console.error('Error in unsafe reuse test:', error.message);
    }
    
    
    
    
    
// Report findings
if (vulnerabilities.length > 0) {
  this.log('\n Potential vulnerabilities found:');
  vulnerabilities.forEach((vuln, i) => {
    this.log(`\n${i+1}. Type: ${vuln.type}`);
    this.log(`   Severity: ${vuln.severity}`);
    this.log(`   Description: ${vuln.description}`);
    this.log(`   Recommendation: ${vuln.recommendation}`);
    
    if (vuln.signal) {
      this.log(`   Affected signal: ${vuln.signal}`);
    }
    
    if (vuln.components) {
      if (vuln.type === 'disconnected-constraint-graph') {
        this.log('   Affected constraints summary:');
        
        // Check if componentSummary exists, if not, create one
        const componentSummary = vuln.componentSummary || vuln.components.map((comp, idx) => ({
          id: idx + 1,
          size: comp.length,
          sampleSignals: comp.length <= 5 ? comp.join(', ') : `${Math.min(3, comp.length)} signal samples`
        }));
        
        this.log(`   - Found ${componentSummary.length} components`);
        
        const sizeCounts = {};
        componentSummary.forEach(comp => {
          const sizeRange = comp.size < 10 ? 'small (< 10)' :
                          comp.size < 100 ? 'medium (10-99)' :
                          comp.size < 1000 ? 'large (100-999)' : 'very large (1000+)';
          sizeCounts[sizeRange] = (sizeCounts[sizeRange] || 0) + 1;
        });
        
        Object.entries(sizeCounts).forEach(([range, count]) => {
          this.log(`   - ${count} ${range} components`);
        });
        
        const largeComponents = componentSummary
          .filter(comp => comp.size > 100)
          .slice(0, 3);
        
        if (largeComponents.length > 0) {
          this.log(`   Notable large components:`);
          largeComponents.forEach(comp => {
            this.log(`   - Component #${comp.id}: ${comp.size} signals`);
          });
        }
      } else {
        // Handle other component types (like unsafe reuse)
        this.log('   Affected components:');
        vuln.components.forEach(comp => {
          this.log(`   - ${comp.component} (${comp.type})`);
        });
      }
    }
  });
} else {
  this.log('\n No potential vulnerabilities detected');
}

return vulnerabilities;
  }
}




module.exports = CircomFuzzer;
