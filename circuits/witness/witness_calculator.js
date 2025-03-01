const { readFile, writeFile } = require('fs').promises;
const { spawn } = require('child_process');
const path = require('path');

/**
 * Generate witness using external command (circom)
 * @param {string} wasmPath - Path to WASM file
 * @param {string} inputPath - Path to input JSON
 * @param {string} outputPath - Path to output witness file
 * @returns {Promise<boolean>} Whether witness generation was successful
 */
async function generateWitness(wasmPath, inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    console.log(`Generating witness: 
      WASM: ${wasmPath}
      Input: ${inputPath}
      Output: ${outputPath}`);

    const process = spawn('node', [
      path.resolve(__dirname, 'generate_witness.js'),
      wasmPath,
      inputPath,
      outputPath
    ], {
      cwd: path.dirname(wasmPath),
      stdio: 'pipe'
    });

    let stdout = '';
    let stderr = '';

    process.stdout.on('data', (data) => {
      stdout += data.toString();
      console.log(`STDOUT: ${data.toString().trim()}`);
    });

    process.stderr.on('data', (data) => {
      stderr += data.toString();
      console.error(`STDERR: ${data.toString().trim()}`);
    });

    process.on('close', (code) => {
      if (code === 0) {
        console.log(`Witness generated successfully: ${outputPath}`);
        resolve(true);
      } else {
        console.error(`Witness generation failed. Exit code: ${code}`);
        console.error('STDOUT:', stdout);
        console.error('STDERR:', stderr);
        resolve(false);
      }
    });

    process.on('error', (error) => {
      console.error('Witness generation error:', error);
      reject(error);
    });
  });
}

// Allow direct script execution
if (require.main === module) {
  if (process.argv.length !== 5) {
    console.log("Usage: node witness_calculator.js <file.wasm> <input.json> <output.wtns>");
    process.exit(1);
  }

  const [wasmPath, inputPath, outputPath] = process.argv.slice(2);

  generateWitness(wasmPath, inputPath, outputPath)
    .then(success => process.exit(success ? 0 : 1))
    .catch(() => process.exit(1));
}

module.exports = { generateWitness };