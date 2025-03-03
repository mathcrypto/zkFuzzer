const fs = require('fs');
const path = require('path');

class R1CSParser {
  /**
   * Advanced R1CS JSON Parser with comprehensive validation
   * @param {Object} options - Parser configuration options
   */
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.strictMode = options.strictMode || true;
    
    // Validation schemas
    this.validationSchemas = {
      r1csStructure: {
        requiredFields: ['constraints', 'signals', 'r1csVersion'],
        constraintStructure: {
          requiredParts: ['l', 'r', 'o']
        },
        signalStructure: {
          requiredFields: ['name']
        }
      }
    };
  }

  /**
   * Parse and validate R1CS JSON file
   * @param {string} r1csJsonPath - Path to R1CS JSON file
   * @returns {Object} Parsed and validated R1CS data
   */
  parseR1CSJson(r1csJsonPath) {
    try {
      // 1. Read file
      const rawData = this.readJsonFile(r1csJsonPath);

      // 2. Validate basic structure
      this.validateR1CSStructure(rawData);

      // 3. Sanitize and process data
      const processedData = this.processR1CSData(rawData);

      // 4. Additional validation checks
      this.performDetailedValidation(processedData);

      return processedData;
    } catch (error) {
      this.handleParsingError(error, r1csJsonPath);
    }
  }

  /**
   * Read JSON file with error handling
   * @param {string} filePath - Path to JSON file
   * @returns {Object} Parsed JSON data
   */
  readJsonFile(filePath) {
    try {
      // Check file existence
      if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
      }

      // Read file
      const rawContent = fs.readFileSync(filePath, 'utf8');

      // Parse JSON
      const parsedData = JSON.parse(rawContent);

      return parsedData;
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(`Invalid JSON format in file: ${filePath}`);
      }
      throw error;
    }
  }

  /**
   * Validate basic R1CS JSON structure
   * @param {Object} data - Parsed R1CS data
   */
  validateR1CSStructure(data) {
    const { requiredFields } = this.validationSchemas.r1csStructure;

    // Check for required top-level fields
    requiredFields.forEach(field => {
      if (!data.hasOwnProperty(field)) {
        throw new Error(`Missing required field: ${field}`);
      }
    });

    // Validate constraints structure
    this.validateConstraintsStructure(data.constraints);

    // Validate signals structure
    this.validateSignalsStructure(data.signals);
  }

  /**
   * Validate constraints structure
   * @param {Array} constraints - R1CS constraints
   */
  validateConstraintsStructure(constraints) {
    const { requiredParts } = this.validationSchemas.r1csStructure.constraintStructure;

    if (!Array.isArray(constraints)) {
      throw new Error('Constraints must be an array');
    }

    constraints.forEach((constraint, index) => {
      // Check for required parts in each constraint
      requiredParts.forEach(part => {
        if (!constraint.hasOwnProperty(part)) {
          throw new Error(`Constraint at index ${index} missing required part: ${part}`);
        }

        // Additional validation for each part
        this.validateConstraintPart(constraint[part], part, index);
      });
    });
  }

  /**
   * Validate individual constraint part
   * @param {Array} part - Constraint part (left, right, output)
   * @param {string} partName - Name of the constraint part
   * @param {number} constraintIndex - Index of the constraint
   */
  validateConstraintPart(part, partName, constraintIndex) {
    if (!Array.isArray(part)) {
      throw new Error(`Constraint part ${partName} at index ${constraintIndex} must be an array`);
    }

    part.forEach((signal, signalIndex) => {
      // Validate signal structure
      if (!signal.hasOwnProperty('signal')) {
        throw new Error(`Missing 'signal' property in ${partName} part at constraint ${constraintIndex}, signal ${signalIndex}`);
      }

      // Validate coefficient
      if (!signal.hasOwnProperty('coefficient')) {
        throw new Error(`Missing 'coefficient' property in ${partName} part at constraint ${constraintIndex}, signal ${signalIndex}`);
      }
    });
  }

  /**
   * Validate signals structure
   * @param {Array} signals - R1CS signals
   */
  validateSignalsStructure(signals) {
    const { requiredFields } = this.validationSchemas.r1csStructure.signalStructure;

    if (!Array.isArray(signals)) {
      throw new Error('Signals must be an array');
    }

    signals.forEach((signal, index) => {
      // Check for required fields
      requiredFields.forEach(field => {
        if (!signal.hasOwnProperty(field)) {
          throw new Error(`Signal at index ${index} missing required field: ${field}`);
        }
      });
    });
  }

  /**
   * Process and sanitize R1CS data
   * @param {Object} rawData - Raw parsed R1CS data
   * @returns {Object} Processed R1CS data
   */
  processR1CSData(rawData) {
    const processedData = { ...rawData };

    // Sanitize constraints
    processedData.constraints = processedData.constraints.map(this.sanitizeConstraint);

    // Sanitize signals
    processedData.signals = processedData.signals.map(this.sanitizeSignal);

    return processedData;
  }

  /**
   * Sanitize individual constraint
   * @param {Object} constraint - Raw constraint
   * @returns {Object} Sanitized constraint
   */
  sanitizeConstraint(constraint) {
    const sanitizedConstraint = { ...constraint };

    // Sanitize each part of the constraint
    ['l', 'r', 'o'].forEach(part => {
      sanitizedConstraint[part] = sanitizedConstraint[part].map(signal => ({
        signal: String(signal.signal),
        coefficient: String(signal.coefficient || '0')
      }));
    });

    return sanitizedConstraint;
  }

  /**
   * Sanitize individual signal
   * @param {Object} signal - Raw signal
   * @returns {Object} Sanitized signal
   */
  sanitizeSignal(signal) {
    return {
      name: String(signal.name),
      ...signal
    };
  }

  /**
   * Perform detailed validation checks
   * @param {Object} processedData - Processed R1CS data
   */
  performDetailedValidation(processedData) {
    // Additional validation checks
    const checks = [
      this.checkSignalUniqueness,
      this.checkConstraintConsistency
    ];

    checks.forEach(check => check.call(this, processedData));
  }

  /**
   * Check signal name uniqueness
   * @param {Object} processedData - Processed R1CS data
   */
  checkSignalUniqueness(processedData) {
    const signalNames = new Set();

    processedData.signals.forEach((signal, index) => {
      if (signalNames.has(signal.name)) {
        throw new Error(`Duplicate signal name found: ${signal.name} at index ${index}`);
      }
      signalNames.add(signal.name);
    });
  }

  /**
   * Check constraint consistency
   * @param {Object} processedData - Processed R1CS data
   */
  checkConstraintConsistency(processedData) {
    processedData.constraints.forEach((constraint, index) => {
      // Additional constraint consistency checks can be added here
      // For example, checking for valid signal references
      ['l', 'r', 'o'].forEach(part => {
        constraint[part].forEach(signal => {
          const signalExists = processedData.signals.some(
            s => s.name === signal.signal
          );

          if (!signalExists) {
            throw new Error(`Invalid signal reference in constraint ${index}: ${signal.signal}`);
          }
        });
      });
    });
  }

  /**
   * Handle parsing errors with detailed logging
   * @param {Error} error - Parsing error
   * @param {string} filePath - Path to the R1CS JSON file
   */
  handleParsingError(error, filePath) {
    const errorDetails = {
      message: error.message,
      file: filePath,
      timestamp: new Date().toISOString()
    };

    // Log error details
    if (this.verbose) {
      console.error('R1CS Parsing Error:', JSON.stringify(errorDetails, null, 2));
    }

    // In strict mode, throw the error
    if (this.strictMode) {
      throw error;
    }

    // In non-strict mode, return null or a default value
    return null;
  }

  /**
   * Logging utility
   * @param {string} message - Log message
   * @param {boolean} isVerbose - Whether message is verbose
   */
  log(message, isVerbose = false) {
    if (!isVerbose || (isVerbose && this.verbose)) {
      console.log(message);
    }
  }
}

module.exports = R1CSParser;