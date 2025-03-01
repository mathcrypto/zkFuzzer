const fs = require('fs');
const path = require('path');
const { generateWitness } = require('./witness_calculator');

// Check if script is run directly
if (require.main === module) {
  if (process.argv.length !== 5) {
    console.log("Usage: node generate_witness.js <file.wasm> <input.json> <output.wtns>");
    process.exit(1);
  }

  const [wasmPath, inputPath, outputPath] = process.argv.slice(2);

  generateWitness(wasmPath, inputPath, outputPath)
    .then(success => process.exit(success ? 0 : 1))
    .catch(() => process.exit(1));
}

module.exports = generateWitness;
