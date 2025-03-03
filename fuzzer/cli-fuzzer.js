#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const CircomFuzzer = require('./circom-fuzzer');

// Preprocessing function to handle input formatting
function preprocessInput(input) {
  // Create a deep copy of the input
  const processedInput = JSON.parse(JSON.stringify(input));
  
  // Ensure authPath is an array
  if (processedInput.authPath && !Array.isArray(processedInput.authPath)) {
    console.warn('Converting authPath to array');
    processedInput.authPath = [processedInput.authPath];
  }
  
  // Ensure authPath has the correct number of elements
  if (processedInput.authPath.length !== 12) {
    console.warn(`Adjusting authPath length to 12 elements`);
    // Pad or truncate to exactly 12 elements
    processedInput.authPath = processedInput.authPath.slice(0, 12);
    while (processedInput.authPath.length < 12) {
      processedInput.authPath.push('0');
    }
  }
  
  return processedInput;
}

// Set up the command-line interface
const program = new Command();

program
  .name('circom-fuzzer')
  .description('A general-purpose security fuzzer for Circom circuits')
  .version('0.1.0');

program
  .argument('<circuit-path>', 'Path to the Circom circuit file (.circom)')
  .argument('[input-file]', 'JSON file with specific input values')
  .option('-o, --output <directory>', 'Output directory for build artifacts', './build')
  .option('-i, --iterations <number>', 'Number of random inputs to generate', '50')
  .option('-t, --input-template <file>', 'JSON file with input template structure')
  .option('-v, --verbose', 'Enable verbose output', false)
  .option('-r, --report <file>', 'Output JSON report file', 'fuzzing-report.json')
  .action(async (circuitPath, inputFile, options) => {
    try {
      console.log(`
╔═══════════════════════════════════════════╗
║                                           ║
║        ZK Circuit Security Fuzzer         ║
║                                           ║
╚═══════════════════════════════════════════╝
`);
      
      // Validate circuit path
      if (!fs.existsSync(circuitPath)) {
        console.error(`Error: Circuit file not found: ${circuitPath}`);
        process.exit(1);
      }
      
      if (!circuitPath.endsWith('.circom')) {
        console.warn('⚠️  Warning: Circuit file does not have .circom extension');
      }
      
      // Load specified input file
      let specificInput = null;
      if (inputFile) {
        try {
          specificInput = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
          
          // Preprocess the input
          specificInput = preprocessInput(specificInput);
          
          // Write preprocessed input to build directory
          const buildInputPath = path.join(options.output, 'input.json');
          fs.writeFileSync(buildInputPath, JSON.stringify(specificInput, null, 2));
        } catch (error) {
          console.error(`Error parsing input file: ${error.message}`);
          process.exit(1);
        }
      }
      
      // Create fuzzer instance
      const fuzzer = new CircomFuzzer(circuitPath, {
        outputDir: options.output,
        iterations: parseInt(options.iterations),
        verbose: options.verbose
      });
      
      // Get input template if provided
      let inputTemplate = null;
      if (options.inputTemplate) {
        if (!fs.existsSync(options.inputTemplate)) {
          console.error(`Error: Input template file not found: ${options.inputTemplate}`);
          process.exit(1);
        }
        
        try {
          inputTemplate = JSON.parse(fs.readFileSync(options.inputTemplate, 'utf8'));
          console.log(`📄 Using input template from: ${options.inputTemplate}`);
        } catch (error) {
          console.error(`Error parsing input template: ${error.message}`);
          process.exit(1);
        }
      }
      
      console.log(`🔍 Analyzing circuit: ${path.basename(circuitPath)}`);
      console.log(`📁 Output directory: ${options.output}`);
      console.log(`🔄 Iterations: ${options.iterations}`);
      
      // Run the fuzzer
      console.log('\n📋 Running security tests...');
      const startTime = Date.now();
      const vulnerabilities = await fuzzer.runAllTests(specificInput || inputTemplate);
      const endTime = Date.now();
      
      // Generate report
      const reportPath = path.join(options.output, options.report);
      const report = {
        circuit: path.basename(circuitPath),
        timestamp: new Date().toISOString(),
        duration: `${((endTime - startTime) / 1000).toFixed(2)} seconds`,
        vulnerabilities: vulnerabilities
      };
      
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      
      // Print summary
      console.log('\n Fuzzing Summary:');
      console.log(`   Circuit: ${path.basename(circuitPath)}`);
      console.log(`   Duration: ${report.duration}`);
      console.log(`   Vulnerabilities found: ${vulnerabilities.length}`);
      console.log(`   Report saved to: ${reportPath}`);
      
      if (vulnerabilities.length > 0) {
        console.log('\n⚠️  WARNING: Potential security issues were found!');
        console.log('   Review the report and address the findings.');
      } else {
        console.log('\n No vulnerabilities detected.');
      }
      
    } catch (error) {
      console.error('\n Error running fuzzer:', error);
      process.exit(1);
    }
  });

// Execute the program
program.parse(process.argv);