//! # Obscura Protocol — Core Groth16 Engine
//!
//! Groth16 proving and verification over BN254 using the arkworks
//! cryptographic library. This module implements the full proving pipeline:
//! elliptic curve operations, bilinear pairings, and R1CS constraint
//! satisfaction.
//!
//! ## Architecture
//!
//! - **Trusted Setup**: `trusted_setup()` runs `Groth16::circuit_specific_setup()`
//!   to generate the proving key (pk) and verification key (vk). This is a
//!   one-time operation per circuit depth. In production, this would be
//!   performed via a Multi-Party Computation (MPC) ceremony.
//!
//! - **Proving**: `Prover::generate_proof()` instantiates the R1CS circuit
//!   with the private witness and calls `Groth16::prove()`, which performs
//!   real scalar multiplications on BN254 G₁/G₂ to produce π = (A, B, C).
//!
//! - **Verification**: `Verifier::verify_proof()` calls `Groth16::verify()`,
//!   which performs 3 bilinear pairings to check:
//!   `e(A, B) = e(α, β) · e(Σxᵢ·ICᵢ, γ) · e(C, δ)`

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore};

use crate::circuit::ObscuraCircuit;
use crate::error::ProtocolError;
use crate::poseidon::{poseidon_config, poseidon_hash};
use crate::tree::MerkleProof;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

// ─── Data Structures ─────────────────────────────────────────────────────────

/// A credential key pair.
///
/// In Obscura, the key pair consists of two BN254 scalar field elements:
/// - `secret_key`: the private authentication credential
/// - `nonce`: a random blinding factor for the commitment
///
/// The commitment `C = Poseidon(sk, nonce)` is inserted into the Merkle tree.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Private authentication key (BN254 scalar).
    pub secret_key: Fr,
    /// Random blinding factor for the commitment (ensures hiding).
    pub nonce: Fr,
}

/// Public inputs to the ZK proof — visible to both prover and verifier.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    /// The Merkle root of the anonymity set.
    pub merkle_root: Fr,
    /// The server-issued authentication challenge.
    pub challenge: Fr,
    /// The nullifier: `Poseidon(sk, challenge)`.
    pub nullifier: Fr,
}

/// Groth16 setup parameters (proving key + verification key).
///
/// Generated once during trusted setup; reused for all proofs at the
/// same tree depth.
pub struct SetupParams {
    /// The proving key — used by the prover to generate proofs.
    /// Contains the toxic waste-derived evaluation points.
    pub proving_key: ProvingKey<Bn254>,
    /// The verification key — used by the verifier to check proofs.
    /// Contains the pairing check elements (α, β, γ, δ, IC).
    pub verifying_key: VerifyingKey<Bn254>,
}

// ─── KeyPair Implementation ──────────────────────────────────────────────────

impl KeyPair {
    /// Generate a new random key pair.
    ///
    /// Both `secret_key` and `nonce` are sampled uniformly at random
    /// from the BN254 scalar field Fr.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        KeyPair {
            secret_key: Fr::rand(rng),
            nonce: Fr::rand(rng),
        }
    }

    /// Compute the Poseidon commitment for this key pair.
    ///
    /// `C = Poseidon(secret_key, nonce)`
    ///
    /// This value is inserted as a leaf into the Merkle tree.
    pub fn commitment(&self, config: &PoseidonConfig<Fr>) -> Fr {
        poseidon_hash(config, &[self.secret_key, self.nonce])
    }

    /// Derive the nullifier for a given challenge.
    ///
    /// `ν = Poseidon(secret_key, challenge)`
    pub fn nullifier(&self, config: &PoseidonConfig<Fr>, challenge: &Fr) -> Fr {
        poseidon_hash(config, &[self.secret_key, *challenge])
    }
}

// ─── Trusted Setup ───────────────────────────────────────────────────────────

/// Run the Groth16 trusted setup ceremony for a given tree depth.
///
/// This generates the structured reference string (SRS) consisting of
/// the proving key and verification key. The setup is performed using
/// a dummy circuit (with `None` witness values) to determine the
/// constraint structure.
///
/// ## Security Note
///
/// In production, this MUST be performed via a Multi-Party Computation
/// (MPC) ceremony to ensure that no single party learns the toxic waste
/// (τ, α, β, γ, δ). If the toxic waste is known, an adversary can
/// forge proofs.
pub fn trusted_setup<R: RngCore + CryptoRng>(
    tree_depth: usize,
    rng: &mut R,
) -> Result<SetupParams, ProtocolError> {
    let config = poseidon_config();
    let dummy_circuit = ObscuraCircuit::dummy(config, tree_depth);

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
        .map_err(|e| ProtocolError::SetupFailure {
            reason: e.to_string(),
        })?;

    Ok(SetupParams {
        proving_key: pk,
        verifying_key: vk,
    })
}

// ─── Prover ──────────────────────────────────────────────────────────────────

/// The Prover generates Groth16 proofs of credential set membership.
///
/// Internally, `Groth16::prove()` performs:
/// 1. Evaluates the R1CS constraint system with the witness.
/// 2. Computes the proof elements via scalar multiplication on BN254:
///    - `A = α + Σ aᵢ·Lᵢ(τ)·G₁ + r·δ·G₁`
///    - `B = β + Σ aᵢ·Rᵢ(τ)·G₂ + s·δ·G₂`
///    - `C = (Σ aᵢ·(β·Lᵢ+α·Rᵢ+Oᵢ)(τ)/δ)·G₁ + A·s + r·B − r·s·δ·G₁`
/// 3. Outputs π = (A, B, C) ∈ G₁ × G₂ × G₁.
pub struct Prover;

impl Prover {
    /// Generate a Groth16 proof.
    pub fn generate_proof<R: RngCore + CryptoRng>(
        keypair: &KeyPair,
        merkle_proof: &MerkleProof,
        public_inputs: &PublicInputs,
        proving_key: &ProvingKey<Bn254>,
        rng: &mut R,
    ) -> Result<Proof<Bn254>, ProtocolError> {
        let config = poseidon_config();

        // Construct the circuit with concrete witness values.
        let circuit = ObscuraCircuit {
            poseidon_config: config,
            tree_depth: merkle_proof.siblings.len(),
            merkle_root: Some(public_inputs.merkle_root),
            nullifier: Some(public_inputs.nullifier),
            secret_key: Some(keypair.secret_key),
            nonce: Some(keypair.nonce),
            challenge: Some(public_inputs.challenge),
            merkle_siblings: merkle_proof.siblings.iter().map(|s| Some(*s)).collect(),
            path_indices: merkle_proof.path_indices.iter().map(|b| Some(*b)).collect(),
        };

        // Run the Groth16 prover.
        Groth16::<Bn254>::prove(proving_key, circuit, rng).map_err(|e| {
            ProtocolError::ProofGenerationFailure {
                reason: e.to_string(),
            }
        })
    }
}

// ─── Verifier ────────────────────────────────────────────────────────────────

/// The Verifier checks Groth16 proofs using bilinear pairings.
///
/// The verification equation is:
///
/// ```text
/// e(A, B) == e(α·G₁, β·G₂) · e(Σ xᵢ·ICᵢ, γ·G₂) · e(C, δ·G₂)
/// ```
///
/// where:
/// - `e` is the BN254 optimal Ate pairing
/// - `(A, B, C)` is the proof
/// - `(α, β, γ, δ, {ICᵢ})` are the verification key elements
/// - `{xᵢ}` are the public inputs (merkle_root, nullifier)
///
/// This involves 3 pairing computations and runs in constant time
/// regardless of the circuit size.
pub struct Verifier;

impl Verifier {
    /// Verify a Groth16 proof against the given public inputs.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if it fails
    /// the pairing check, or `Err(...)` if verification encounters an error.
    pub fn verify_proof(
        proof: &Proof<Bn254>,
        public_inputs: &PublicInputs,
        verifying_key: &VerifyingKey<Bn254>,
    ) -> Result<bool, ProtocolError> {
        // Public inputs must match the order allocated in the circuit:
        // [merkle_root, nullifier]
        let inputs = vec![public_inputs.merkle_root, public_inputs.nullifier];

        Groth16::<Bn254>::verify(verifying_key, &inputs, proof)
            .map_err(|_| ProtocolError::InvalidProof)
    }
}

/// Serialize a Groth16 proof to compressed bytes.
pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| ProtocolError::SerializationError {
            reason: e.to_string(),
        })?;
    Ok(bytes)
}

/// Deserialize a Groth16 proof from compressed bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>, ProtocolError> {
    Proof::<Bn254>::deserialize_compressed(bytes).map_err(|e| {
        ProtocolError::SerializationError {
            reason: e.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleTree;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_full_groth16_flow() {
        let mut rng = StdRng::seed_from_u64(42);
        let config = poseidon_config();

        // Setup: build tree
        let mut tree = MerkleTree::with_config(config.clone());
        for _ in 0..3 {
            let dummy = KeyPair::generate(&mut rng);
            tree.insert(dummy.commitment(&config)).unwrap();
        }
        let user = KeyPair::generate(&mut rng);
        let user_idx = tree.insert(user.commitment(&config)).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(user_idx).unwrap();
        let tree_depth = tree.depth();

        // Trusted setup
        let params = trusted_setup(tree_depth, &mut rng).unwrap();

        // Challenge + nullifier
        let challenge = Fr::rand(&mut rng);
        let nullifier = user.nullifier(&config, &challenge);
        let public_inputs = PublicInputs {
            merkle_root: root,
            challenge,
            nullifier,
        };

        // Prove
        let proof =
            Prover::generate_proof(&user, &merkle_proof, &public_inputs, &params.proving_key, &mut rng)
                .unwrap();

        // Verify
        let valid =
            Verifier::verify_proof(&proof, &public_inputs, &params.verifying_key).unwrap();
        assert!(valid, "Valid proof must pass verification");
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut rng = StdRng::seed_from_u64(43);
        let config = poseidon_config();

        let mut tree = MerkleTree::with_config(config.clone());
        let user = KeyPair::generate(&mut rng);
        tree.insert(user.commitment(&config)).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(0).unwrap();
        let tree_depth = tree.depth();

        let params = trusted_setup(tree_depth, &mut rng).unwrap();
        let challenge = Fr::rand(&mut rng);
        let nullifier = user.nullifier(&config, &challenge);
        let public_inputs = PublicInputs {
            merkle_root: root,
            challenge,
            nullifier,
        };

        let proof =
            Prover::generate_proof(&user, &merkle_proof, &public_inputs, &params.proving_key, &mut rng)
                .unwrap();

        // Tamper: serialize, flip bytes, deserialize
        let mut bytes = serialize_proof(&proof).unwrap();
        bytes[0] ^= 0xFF;
        // Deserialization of corrupted bytes should fail or produce invalid proof
        match deserialize_proof(&bytes) {
            Ok(tampered_proof) => {
                let result =
                    Verifier::verify_proof(&tampered_proof, &public_inputs, &params.verifying_key);
                // Should either error or return false
                match result {
                    Ok(valid) => assert!(!valid, "Tampered proof must not verify"),
                    Err(_) => {} // Also acceptable — invalid curve point
                }
            }
            Err(_) => {} // Deserialization failure is expected for corrupted bytes
        }
    }

    #[test]
    fn test_wrong_public_inputs_rejected() {
        let mut rng = StdRng::seed_from_u64(44);
        let config = poseidon_config();

        let mut tree = MerkleTree::with_config(config.clone());
        let user = KeyPair::generate(&mut rng);
        tree.insert(user.commitment(&config)).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(0).unwrap();
        let tree_depth = tree.depth();

        let params = trusted_setup(tree_depth, &mut rng).unwrap();
        let challenge = Fr::rand(&mut rng);
        let nullifier = user.nullifier(&config, &challenge);
        let public_inputs = PublicInputs {
            merkle_root: root,
            challenge,
            nullifier,
        };

        let proof =
            Prover::generate_proof(&user, &merkle_proof, &public_inputs, &params.proving_key, &mut rng)
                .unwrap();

        // Verify with wrong nullifier
        let wrong_inputs = PublicInputs {
            merkle_root: root,
            challenge,
            nullifier: Fr::rand(&mut rng), // wrong!
        };

        let valid =
            Verifier::verify_proof(&proof, &wrong_inputs, &params.verifying_key).unwrap();
        assert!(!valid, "Wrong public inputs must fail verification");
    }
}
