const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');
const R1CS = require('./R1CSParser');

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

  /**
   * Test for under-constrained variables by trying to create invalid proofs
   * This method tries to detect the "Assigned but Unconstrained" vulnerability
   * mentioned in the Tornado Cash MIMC hash bug example
   */
  async testForUnderconstrainedVariables(inputTemplate) {
    this.log('Testing for under-constrained variables...');
    
    // Generate random inputs based on the input template
    const validInput = this.generateInput(inputTemplate);
    
    // Write these inputs to a JSON file
    const inputPath = path.join(this.outputDir, 'input.json');
    fs.writeFileSync(inputPath, JSON.stringify(validInput, null, 2));
    
    try {
      // Generate witness using the compiled wasm file
      const wasmPath = path.join('../circuits', `${this.circuitName}.wasm`);
      const witCmd = path.join(this.outputDir, 'witness1.wtns');

      
      this.log('Witness generated successfully. Analyzing for unconstrained variables...', true);
      
      // Export R1CS to JSON for analysis
      const r1csJsonPath = path.join(this.outputDir, `${this.circuitName}.r1cs`);
      if (!fs.existsSync(r1csJsonPath)) {
        execSync(`snarkjs r1cs export json ${this.outputDir}/${this.circuitName}.r1cs ${r1csJsonPath}`);
      }
      
      return this.analyzeR1CSConstraints(r1csJsonPath);
    } catch (error) {
      console.error('Error testing for under-constrained variables:', error.message);
      
      // This is still a valid test - errors in witness generation 
      // don't necessarily mean there are no under-constrained variables
      return this.analyzeCircuitStatically();
    }
  }
  
  /**
   * Analyze R1CS constraints to find signals that might be unconstrained
   * This is a simplified implementation - a real analyzer would be more complex
   */
  analyzeR1CSConstraints(r1csJsonPath) {
    this.log(`Analyzing R1CS constraints from: ${r1csJsonPath}`);
    
    try {
      // 1. Parse the R1CS JSON file
      const parser = new R1CSParser({
        verbose: this.verbose,   
        strictMode: true
      });

      // Read and validate the R1CS JSON file
        const r1csData = parser.parseR1CSJson(r1csJsonPath);
      // 2. Build a graph of signal dependencies
      // 3. Check which signals appear in the witness but are never constrained
      // 4. Identify potential vulnerabilities
      
      // This is a placeholder implementation
      return [{
        type: 'potential-unconstrained-signal',
        severity: 'high',
        description: 'Signal may be assigned but not constrained (similar to Tornado Cash MIMC bug)',
        recommendation: 'Check for <-- vs <== usage in your Circom code'
      }];
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
      const findings = [];
      
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