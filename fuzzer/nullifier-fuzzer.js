const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Paths
const BASE_DIR = path.resolve(__dirname, '..');
const CIRCUITS_DIR = path.resolve(BASE_DIR, 'circuits');
const FUZZER_DIR = path.resolve(BASE_DIR, 'fuzzer');
const TEST_INPUTS_DIR = path.resolve(FUZZER_DIR, 'test-inputs');

/**
 * Nullifier Reuse Vulnerability Analyzer
 */
class NullifierReuseAnalyzer {
  /**
   * Generate test cases to probe nullifier reuse vulnerability
   * @returns {Array} Vulnerability test cases
   */
  generateVulnerabilityTestCases() {
    // Strategic test scenarios to exploit under-constrained nullifier calculation
    const testScenarios = [
      {
        name: "Identical Leaf, Different Voter Indices",
        description: "Test nullifier generation with same leaf but different voter indices",
        leafValue: 12345,
        voterIndices: [0, 1, 2, 3],
        merkleRoot: '12345' // Simplified for testing
      },
      {
        name: "Similar Leaves, Different Voter Indices",
        description: "Test nullifier generation with similar leaves",
        leafValues: [12345, 54321, 99999],
        voterIndices: [0, 1, 2],
        merkleRoot: '54321' // Another simplified root
      }
    ];

    const testCases = [];

    testScenarios.forEach(scenario => {
      // Use multiple leaf values if provided, otherwise use a single leaf
      const leaves = scenario.leafValues || [scenario.leafValue];

      leaves.forEach((leafValue, leafIndex) => {
        scenario.voterIndices.forEach(voterIndex => {
          testCases.push({
            scenario: scenario.name,
            description: scenario.description,
            merkleRoot: scenario.merkleRoot,
            voterIndex: voterIndex.toString(),
            leafValue: leafValue.toString(),
            authPath: [leafValue.toString(), '0', '0'] // Simplified auth path
          });
        });
      });
    });

    return testCases;
  }

  /**
   * Analyze nullifier generation for potential reuse
   * @param {Array} testCases - Test cases to analyze
   * @param {Object} poseidon - Poseidon hash function
   * @returns {Object} Vulnerability analysis report
   */
  analyzeNullifierReuse(testCases, poseidon) {
    const F = poseidon.F;
    const nullifierHashes = {};
    const vulnerabilities = [];

    testCases.forEach(testCase => {
      // Calculate nullifier hash
      const nullifierHash = F.toString(poseidon([
        F.e(testCase.merkleRoot), 
        F.e(testCase.leafValue)
      ]));

      // Check for nullifier hash reuse
      if (!nullifierHashes[nullifierHash]) {
        nullifierHashes[nullifierHash] = [];
      }
      
      nullifierHashes[nullifierHash].push(testCase);
    });

    // Identify vulnerabilities
    Object.entries(nullifierHashes).forEach(([hash, cases]) => {
      if (cases.length > 1) {
        vulnerabilities.push({
          type: "Nullifier Reuse",
          severity: "Critical",
          description: "Multiple inputs generate identical nullifier hash",
          details: {
            nullifierHash: hash,
            duplicateCases: cases
          }
        });
      }
    });

    return {
      summary: {
        totalTestCases: testCases.length,
        uniqueNullifiers: Object.keys(nullifierHashes).length,
        vulnerabilitiesDetected: vulnerabilities.length
      },
      vulnerabilities,
      nullifierHashes
    };
  }
}

/**
 * Run comprehensive nullifier reuse vulnerability test
 */
async function runNullifierVulnerabilityTest() {
  console.log('🔍 Analyzing Nullifier Reuse Vulnerability');
  
  // Load Poseidon hash function
  const circomlibjs = require('circomlibjs');
  const poseidon = await circomlibjs.buildPoseidon();
  
  // Create vulnerability analyzer
  const analyzer = new NullifierReuseAnalyzer();
  
  // Generate test cases
  const testCases = analyzer.generateVulnerabilityTestCases();
  
  // Analyze nullifier reuse
  const report = analyzer.analyzeNullifierReuse(testCases, poseidon);
  
  // Visualization and detailed output
  console.log('\n📊 Nullifier Reuse Analysis Results');
  console.log('====================================');
  
  console.log('\n🔬 Test Case Summary:');
  console.log(`Total Test Cases: ${report.summary.totalTestCases}`);
  console.log(`Unique Nullifier Hashes: ${report.summary.uniqueNullifiers}`);
  console.log(`Vulnerabilities Detected: ${report.summary.vulnerabilitiesDetected}`);
  
  // Detailed vulnerability explanation
  if (report.vulnerabilities.length > 0) {
    console.log('\n🚨 Vulnerabilities Detected:');
    report.vulnerabilities.forEach((vuln, index) => {
      console.log(`\nVulnerability ${index + 1}: ${vuln.type}`);
      console.log(`Severity: ${vuln.severity}`);
      console.log(`Description: ${vuln.description}`);
      console.log('Duplicate Nullifier Hash:', vuln.details.nullifierHash);
      console.log('Duplicate Cases:');
      vuln.details.duplicateCases.forEach(cases => {
        console.log(JSON.stringify(cases, null, 2));
      });
    });
  } else {
    console.log('\n✅ No Nullifier Reuse Vulnerabilities Detected');
  }
  
  // Save detailed report
  const reportFile = path.join(TEST_INPUTS_DIR, 'nullifier_reuse_vulnerability_report.json');
  fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
  
  console.log(`\n📋 Detailed report saved to: ${reportFile}`);
  
  return report;
}

// Execute the vulnerability test
runNullifierVulnerabilityTest().catch(error => {
  console.error('Nullifier Vulnerability Test Failed:', error);
  process.exit(1);
});