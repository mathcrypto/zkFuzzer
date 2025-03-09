#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * A utility to inspect a compiled Circom circuit and determine its exact input structure
 */
async function inspectCircuit(circuitPath, buildDir = './build') {
  const circuitName = path.basename(circuitPath, '.circom');
  
  console.log(`Inspecting circuit: ${circuitPath}`);
  
  // Ensure the circuit is compiled
  const wasmPath = path.join(buildDir, `${circuitName}_js/${circuitName}.wasm`);
  if (!fs.existsSync(wasmPath)) {
    console.log('Circuit not compiled, compiling now...');
    try {
      execSync(`circom ${circuitPath} --wasm --r1cs -o ${buildDir}`);
    } catch (error) {
      console.error('Error compiling circuit:', error.message);
      return null;
    }
  }
  
  // Look for symbols.json file which contains input information
  const symbolsPath = path.join(buildDir, `${circuitName}_js/${circuitName}.sym`);
  const r1csInfoPath = path.join(buildDir, `${circuitName}.r1cs.json`);
  
  try {
    // Try to get information from the wasm module
    // First, export r1cs to JSON if needed
    if (!fs.existsSync(r1csInfoPath)) {
      console.log('Exporting R1CS to JSON...');
      execSync(`snarkjs r1cs export json ${buildDir}/${circuitName}.r1cs ${r1csInfoPath}`);
    }
    
    // Read the R1CS info
    const r1csInfo = JSON.parse(fs.readFileSync(r1csInfoPath, 'utf8'));
    
    // Extract input information
    const inputs = {};
    let inputSection = false;
    
    // Parse inputs from R1CS info
    console.log('\nCircuit inputs:');
    
    // Create a minimal input JSON that should work with the circuit
    const minimalInput = {};
    const inputSignals = [];
    
    // Create a temporary input file for testing
    for (let i = 1; i < r1csInfo.signalNames.length; i++) {
      const signalName = r1csInfo.signalNames[i][0];
      if (signalName.startsWith('main.')) {
        // Remove 'main.' prefix
        const shortName = signalName.substring(5);
        
        // Check if it's an input signal
        if (shortName.startsWith('input_')) {
          const inputName = shortName.substring(6);
          console.log(`- ${inputName}`);
          
          // If it includes array indices (e.g., [0], [1], etc.)
          const match = inputName.match(/^([^\[]+)(?:\[(\d+)\])?$/);
          if (match) {
            const baseName = match[1];
            const index = match[2];
            
            if (index !== undefined) {
              // This is an array element
              if (!minimalInput[baseName]) {
                minimalInput[baseName] = [];
              }
              
              // Make sure the array is big enough
              const arrayIndex = parseInt(index);
              while (minimalInput[baseName].length <= arrayIndex) {
                minimalInput[baseName].push("0");
              }
            } else {
              // This is a scalar input
              minimalInput[baseName] = "0";
            }
            
            // Keep track of all input signals
            if (!inputSignals.includes(baseName)) {
              inputSignals.push(baseName);
            }
          }
        }
      }
    }
    
    console.log('\nDetected input structure:');
    for (const name of inputSignals) {
      if (Array.isArray(minimalInput[name])) {
        console.log(`- ${name}: array of length ${minimalInput[name].length}`);
      } else {
        console.log(`- ${name}: scalar value`);
      }
    }
    
    // Save the minimal input template
    const minimalInputPath = path.join(buildDir, 'minimal_input.json');
    fs.writeFileSync(minimalInputPath, JSON.stringify(minimalInput, null, 2));
    console.log(`\nSaved minimal input template to: ${minimalInputPath}`);
    
    return minimalInput;
  } catch (error) {
    console.error('Error inspecting circuit:', error.message);
    
    // Alternative approach: try to infer from circuit file directly
    console.log('\nTrying to infer from circuit file directly...');
    
    try {
      const circuitContent = fs.readFileSync(circuitPath, 'utf8');
      
      // Look for input signal declarations
      const inputRegex = /signal\s+input\s+(\w+)(?:\[(\d+)\])?/g;
      const inferred = {};
      let match;
      
      console.log('Detected input signals (from source):');
      while ((match = inputRegex.exec(circuitContent)) !== null) {
        const signalName = match[1];
        const arraySize = match[2];
        
        if (arraySize) {
          console.log(`- ${signalName}: array of length ${arraySize}`);
          inferred[signalName] = Array(parseInt(arraySize)).fill("0");
        } else {
          console.log(`- ${signalName}: scalar value`);
          inferred[signalName] = "0";
        }
      }
      
      const inferredPath = path.join(buildDir, 'inferred_input.json');
      fs.writeFileSync(inferredPath, JSON.stringify(inferred, null, 2));
      console.log(`\nSaved inferred input template to: ${inferredPath}`);
      
      return inferred;
    } catch (error) {
      console.error('Error inferring from circuit file:', error.message);
      return null;
    }
  }
}

// Run as standalone script if executed directly
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length < 1) {
    console.log('Usage: node circuit-inspector.js <circuit-path> [build-dir]');
    process.exit(1);
  }
  
  const circuitPath = args[0];
  const buildDir = args.length > 1 ? args[1] : './build';
  
  inspectCircuit(circuitPath, buildDir).catch(console.error);
}

module.exports = inspectCircuit;