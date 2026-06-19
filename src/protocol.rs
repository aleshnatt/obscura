//! # Obscura Protocol — Core Lattice-Based ZK Engine
//!
//! Post-quantum proving and verification over Module-LWE using the
//! Fiat-Shamir with Aborts paradigm. This module provides the high-level
//! protocol API for key generation, proof creation, and verification.
//!
//! ## Architecture
//!
//! - **No Trusted Setup**: Unlike Groth16, the lattice-based protocol uses
//!   public MLWE parameters (a uniform matrix A) that require no multi-party
//!   ceremony. Parameters can be generated from a public seed.
//!
//! - **Proving**: `Prover::generate_proof()` invokes the lattice ZK protocol:
//!   sample masking vector, compute commitment, derive Fiat-Shamir challenge,
//!   compute response with rejection sampling.
//!
//! - **Verification**: `Verifier::verify_proof()` checks the norm bound,
//!   challenge consistency, algebraic relation, and Merkle membership.
//!
//! ## Security
//!
//! Security is based on the hardness of Module-LWE and Module-SIS in the
//! Quantum Random Oracle Model (QROM), providing ≥128-bit classical and
//! ≥64-bit quantum security at NIST Category 1.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use crate::mlwe::{self, MlweKeyPair, MlweParams};
use crate::poly::PolyVec;
use crate::tree::MerkleProof;
use crate::zk_auth::{self, AuthProof};

// ─── Data Structures ─────────────────────────────────────────────────────────

/// A credential key pair for the post-quantum protocol.
///
/// Wraps an MLWE key pair:
/// - `secret_key`: s ∈ R_q^k with small CBD coefficients.
/// - `public_key`: b = A·s + e mod q.
///
/// The commitment `SHAKE-256("COM_DOM" ∥ b)` is inserted into the Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The underlying MLWE key pair.
    pub inner: MlweKeyPair,
}

/// Public inputs to the ZK proof — visible to both prover and verifier.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    /// The Merkle root of the anonymity set (32-byte SHAKE-256 hash).
    pub merkle_root: [u8; 32],
    /// The session-specific challenge scope (arbitrary bytes).
    pub scope: Vec<u8>,
    /// The nullifier: SHAKE-256("NUL_DOM" ∥ s ∥ scope).
    pub nullifier: [u8; 32],
}

// ─── KeyPair Implementation ──────────────────────────────────────────────────

impl KeyPair {
    /// Generate a new random MLWE key pair.
    ///
    /// Samples s, e ← CBD(η)^k and computes b = A·s + e mod q.
    pub fn generate(params: &MlweParams, rng: &mut dyn RngCore) -> Self {
        KeyPair {
            inner: mlwe::keygen(params, rng),
        }
    }

    /// Access the secret key vector.
    pub fn secret_key(&self) -> &PolyVec {
        &self.inner.secret_key
    }

    /// Access the public key vector.
    pub fn public_key(&self) -> &PolyVec {
        &self.inner.public_key
    }

    /// Compute the SHAKE-256 commitment hash for this key pair's public key.
    ///
    /// `commitment = SHAKE-256("COM_DOM" ∥ serialize(b))`, 32 bytes.
    ///
    /// This value is inserted as a leaf into the Merkle tree.
    pub fn commitment(&self) -> [u8; 32] {
        mlwe::commitment_hash(&self.inner.public_key)
    }

    /// Derive the nullifier for a given scope.
    ///
    /// `nullifier = SHAKE-256("NUL_DOM" ∥ serialize(s) ∥ scope)`, 32 bytes.
    pub fn nullifier(&self, scope: &[u8]) -> [u8; 32] {
        zk_auth::derive_nullifier(&self.inner.secret_key, scope)
    }
}

// ─── Prover ──────────────────────────────────────────────────────────────────

/// The Prover generates lattice-based ZK proofs of credential set membership.
///
/// The proving protocol uses Fiat-Shamir with Aborts:
/// 1. Sample masking vector y ← Uniform([-γ₁+1, γ₁])^{k·n}.
/// 2. Compute commitment w = A · y mod q.
/// 3. Derive challenge c via SHAKE-256 from the transcript.
/// 4. Compute response z = y + c·s mod q.
/// 5. Rejection sampling: abort if ‖z‖∞ ≥ γ₁ - β.
///
/// Expected ~4-5 attempts per successful proof due to rejection sampling.
pub struct Prover;

impl Prover {
    /// Generate a lattice-based ZK authorization proof.
    pub fn generate_proof(
        params: &MlweParams,
        keypair: &KeyPair,
        merkle_proof: &MerkleProof,
        public_inputs: &PublicInputs,
        rng: &mut dyn RngCore,
    ) -> Result<AuthProof, ProtocolError> {
        zk_auth::prove(
            params,
            &keypair.inner,
            merkle_proof,
            &public_inputs.merkle_root,
            &public_inputs.scope,
            rng,
        )
    }
}

// ─── Verifier ────────────────────────────────────────────────────────────────

/// The Verifier checks lattice-based ZK proofs.
///
/// Verification checks:
/// 1. ‖z‖∞ < γ₁ - β (response norm bound).
/// 2. Challenge consistency (recomputed from transcript).
/// 3. Algebraic relation: ‖A·z - w - c·b‖∞ < τ·η·n + 1.
/// 4. Merkle membership (commitment hash ↔ root).
///
/// Verification runs in constant time relative to the anonymity set size.
pub struct Verifier;

impl Verifier {
    /// Verify a lattice-based ZK authorization proof.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if it fails
    /// any verification check.
    pub fn verify_proof(
        params: &MlweParams,
        proof: &AuthProof,
        keypair: &KeyPair,
        public_inputs: &PublicInputs,
    ) -> Result<bool, ProtocolError> {
        zk_auth::verify(
            params,
            proof,
            &keypair.inner.public_key,
            &public_inputs.merkle_root,
            &public_inputs.scope,
        )
    }
}

/// Serialize an AuthProof to JSON bytes.
pub fn serialize_proof(proof: &AuthProof) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(proof).map_err(|e| ProtocolError::SerializationError {
        reason: e.to_string(),
    })
}

/// Deserialize an AuthProof from JSON bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Result<AuthProof, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|e| ProtocolError::SerializationError {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleTree;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_full_lattice_zk_flow() {
        let mut rng = StdRng::seed_from_u64(42);

        // Generate MLWE parameters (public matrix A).
        let params = MlweParams::generate(&mut rng);

        // Build anonymity set.
        let mut tree = MerkleTree::new();
        for _ in 0..3 {
            let dummy = KeyPair::generate(&params, &mut rng);
            tree.insert(dummy.commitment()).unwrap();
        }

        // Register user.
        let user = KeyPair::generate(&params, &mut rng);
        let user_idx = tree.insert(user.commitment()).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(user_idx).unwrap();

        // Challenge + nullifier.
        let scope = b"session_challenge_xyz".to_vec();
        let nullifier = user.nullifier(&scope);
        let public_inputs = PublicInputs {
            merkle_root: root,
            scope: scope.clone(),
            nullifier,
        };

        // Prove.
        let proof =
            Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
                .unwrap();

        // Verify.
        let valid = Verifier::verify_proof(&params, &proof, &user, &public_inputs).unwrap();
        assert!(valid, "Valid proof must pass verification");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(43);
        let params = MlweParams::generate(&mut rng);

        let mut tree = MerkleTree::new();
        let user = KeyPair::generate(&params, &mut rng);
        tree.insert(user.commitment()).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(0).unwrap();

        let scope = b"serialize_test".to_vec();
        let nullifier = user.nullifier(&scope);
        let public_inputs = PublicInputs {
            merkle_root: root,
            scope: scope.clone(),
            nullifier,
        };

        let proof =
            Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
                .unwrap();

        // Serialize and deserialize.
        let bytes = serialize_proof(&proof).unwrap();
        let recovered = deserialize_proof(&bytes).unwrap();

        // Verify the recovered proof.
        let valid = Verifier::verify_proof(&params, &recovered, &user, &public_inputs).unwrap();
        assert!(valid, "Deserialized proof must still verify");
    }

    #[test]
    fn test_wrong_scope_rejected() {
        let mut rng = StdRng::seed_from_u64(44);
        let params = MlweParams::generate(&mut rng);

        let mut tree = MerkleTree::new();
        let user = KeyPair::generate(&params, &mut rng);
        tree.insert(user.commitment()).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(0).unwrap();

        let scope = b"correct_scope".to_vec();
        let nullifier = user.nullifier(&scope);
        let public_inputs = PublicInputs {
            merkle_root: root,
            scope,
            nullifier,
        };

        let proof =
            Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
                .unwrap();

        // Verify with wrong scope.
        let wrong_inputs = PublicInputs {
            merkle_root: root,
            scope: b"wrong_scope".to_vec(),
            nullifier,
        };

        let valid = Verifier::verify_proof(&params, &proof, &user, &wrong_inputs).unwrap();
        assert!(!valid, "Wrong scope must fail verification");
    }
}
