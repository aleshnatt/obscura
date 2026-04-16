//! # Obscura Protocol — Error Definitions
//!
//! Comprehensive error taxonomy for the Obscura protocol engine.

use thiserror::Error;

/// Unified error type for all Obscura protocol operations.
#[derive(Debug, Error)]
pub enum ProtocolError {
    // ─── Setup Errors ────────────────────────────────────────────────────

    /// The Groth16 trusted setup (CRS generation) failed.
    #[error("Setup error: trusted setup failed — {reason}")]
    SetupFailure { reason: String },

    // ─── Merkle Tree Errors ──────────────────────────────────────────────

    /// The Merkle tree contains no leaves.
    #[error("Merkle tree error: tree is empty — at least one leaf must be inserted before computing the root")]
    EmptyTree,

    /// The requested leaf index is out of bounds.
    #[error("Merkle tree error: invalid leaf index {index} — tree contains only {total_leaves} leaves")]
    InvalidLeafIndex { index: usize, total_leaves: usize },

    /// Internal failure during tree construction.
    #[error("Merkle tree error: tree construction failure — {reason}")]
    TreeConstructionFailure { reason: String },

    // ─── Proof Errors ────────────────────────────────────────────────────

    /// The prover could not generate a valid ZK proof.
    #[error("Proof generation error: failed to generate Groth16 proof — {reason}")]
    ProofGenerationFailure { reason: String },

    /// The Merkle inclusion witness is malformed.
    #[error("Proof error: invalid Merkle witness — the sibling path does not reconstruct the claimed root")]
    InvalidWitness,

    /// The commitment does not match the expected hash.
    #[error("Proof error: commitment mismatch — computed commitment does not match the leaf in the Merkle tree")]
    CommitmentMismatch,

    // ─── Verification Errors ─────────────────────────────────────────────

    /// The ZK proof failed Groth16 pairing-based verification.
    #[error("Verification error: invalid Groth16 proof — pairing check failed")]
    InvalidProof,

    /// The Merkle root embedded in the proof does not match.
    #[error("Verification error: Merkle root mismatch — proof root does not match the expected anonymity set root")]
    RootMismatch,

    /// The server-issued challenge is invalid.
    #[error("Verification error: challenge validation failed")]
    ChallengeFailure,

    // ─── Serialization Errors ────────────────────────────────────────────

    /// Proof serialization or deserialization failed.
    #[error("Serialization error: {reason}")]
    SerializationError { reason: String },

    // ─── Circuit Errors ──────────────────────────────────────────────────

    /// R1CS constraint synthesis failed.
    #[error("Circuit error: constraint synthesis failed — {reason}")]
    SynthesisError { reason: String },

    // ─── Generic Cryptographic Errors ────────────────────────────────────

    /// A low-level cryptographic operation failed.
    #[error("Cryptographic error: {reason}")]
    CryptoError { reason: String },
}
