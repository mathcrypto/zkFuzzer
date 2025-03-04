# Directories
BUILD_DIR := ./build
SETUP_DIR := ./setup
CIRCUIT_DIR := ../circuits
CIRCUIT := VotingCircuit
PTAU_FILE := $(BUILD_DIR)/pot14_final.ptau

# Targets
all: setup compile witness proof verify

## ======= Trusted Setup =======
$(BUILD_DIR)/pot14_0000.ptau:
	@ mkdir -p $(BUILD_DIR)
	snarkjs powersoftau new bn128 14 $(BUILD_DIR)/pot14_0000.ptau -v

$(BUILD_DIR)/pot14_0001.ptau: $(BUILD_DIR)/pot14_0000.ptau
	snarkjs powersoftau contribute $(BUILD_DIR)/pot14_0000.ptau $(BUILD_DIR)/pot14_0001.ptau --name="First Contribution" -v

$(BUILD_DIR)/pot14_beacon.ptau: $(BUILD_DIR)/pot14_0001.ptau
	snarkjs powersoftau beacon $(BUILD_DIR)/pot14_0001.ptau $(BUILD_DIR)/pot14_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon" -v

$(BUILD_DIR)/pot14_final.ptau: $(BUILD_DIR)/pot14_beacon.ptau
	snarkjs powersoftau prepare phase2 $(BUILD_DIR)/pot14_beacon.ptau $(BUILD_DIR)/pot14_final.ptau -v

## ======= Compile Circuit =======
$(BUILD_DIR)/$(CIRCUIT).r1cs: $(CIRCUIT_DIR)/$(CIRCUIT).circom
	@ mkdir -p $(BUILD_DIR)
	circom --r1cs --wasm -o $(BUILD_DIR) $(CIRCUIT_DIR)/$(CIRCUIT).circom -l ../app/node_modules/

$(BUILD_DIR)/$(CIRCUIT).wasm: $(CIRCUIT_DIR)/$(CIRCUIT).circom
	@ mkdir -p $(BUILD_DIR)
	circom --wasm -o $(BUILD_DIR) $(CIRCUIT_DIR)/$(CIRCUIT).circom -l ../app/node_modules/; mv $(BUILD_DIR)/$(CIRCUIT)_js/$(CIRCUIT).wasm $(BUILD_DIR)/

## ======= Setup Proving Key =======
$(BUILD_DIR)/$(CIRCUIT)_0000.zkey: $(BUILD_DIR)/$(CIRCUIT).r1cs $(PTAU_FILE)
	snarkjs groth16 setup $(BUILD_DIR)/$(CIRCUIT).r1cs $(PTAU_FILE) $(BUILD_DIR)/$(CIRCUIT)_0000.zkey

$(BUILD_DIR)/$(CIRCUIT)_0001.zkey: $(BUILD_DIR)/$(CIRCUIT)_0000.zkey
	snarkjs zkey contribute $(BUILD_DIR)/$(CIRCUIT)_0000.zkey $(BUILD_DIR)/$(CIRCUIT)_0001.zkey --name="Fuzzer Contributor"

$(BUILD_DIR)/$(CIRCUIT)_final.zkey: $(BUILD_DIR)/$(CIRCUIT)_0001.zkey
	snarkjs zkey beacon $(BUILD_DIR)/$(CIRCUIT)_0001.zkey $(BUILD_DIR)/$(CIRCUIT)_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"

$(BUILD_DIR)/verification_key.json: $(BUILD_DIR)/$(CIRCUIT)_final.zkey
	snarkjs zkey export verificationkey $(BUILD_DIR)/$(CIRCUIT)_final.zkey $(BUILD_DIR)/verification_key.json

## ======= Generate Witness =======
$(BUILD_DIR)/witness1.wtns: $(BUILD_DIR)/$(CIRCUIT).wasm test-inputs/$(CIRCUIT)-input.json
	snarkjs wtns calculate $(BUILD_DIR)/$(CIRCUIT).wasm test-inputs/$(CIRCUIT)-input.json $(BUILD_DIR)/witness1.wtns

## ======= Generate Proof =======
$(BUILD_DIR)/proof.json: $(BUILD_DIR)/$(CIRCUIT)_final.zkey $(BUILD_DIR)/witness1.wtns
	snarkjs groth16 prove $(BUILD_DIR)/$(CIRCUIT)_final.zkey $(BUILD_DIR)/witness1.wtns $(BUILD_DIR)/proof.json $(BUILD_DIR)/public.json

## ======= Verify Proof =======
verify: $(BUILD_DIR)/proof.json $(BUILD_DIR)/verification_key.json
	snarkjs groth16 verify $(BUILD_DIR)/verification_key.json $(BUILD_DIR)/public.json $(BUILD_DIR)/proof.json

## ======= Setup Directory =======
$(SETUP_DIR)/$(CIRCUIT)_final.zkey: $(BUILD_DIR)/$(CIRCUIT)_final.zkey
	@ mkdir -p $(SETUP_DIR)
	cp $(BUILD_DIR)/$(CIRCUIT)_final.zkey $(SETUP_DIR)

$(SETUP_DIR)/$(CIRCUIT).wasm: $(BUILD_DIR)/$(CIRCUIT).wasm
	@ mkdir -p $(SETUP_DIR)
	cp $(BUILD_DIR)/$(CIRCUIT).wasm $(SETUP_DIR)

$(SETUP_DIR)/verification_key.json: $(BUILD_DIR)/verification_key.json
	@ mkdir -p $(SETUP_DIR)
	cp $(BUILD_DIR)/verification_key.json $(SETUP_DIR)

setup: $(SETUP_DIR)/$(CIRCUIT)_final.zkey $(SETUP_DIR)/$(CIRCUIT).wasm $(SETUP_DIR)/verification_key.json

## ======= Clean Commands =======
clean:
	rm -rf $(BUILD_DIR)

dist-clean: clean
	rm -rf $(SETUP_DIR)

.PHONY: all setup clean dist-clean compile witness proof verify
