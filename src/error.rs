//! Error taxonomy for Obscura protocol operations.
//!
//! This module does not implement cryptographic checks itself. It records the
//! structural, serialization, and verification failures emitted by modules that
//! process untrusted Merkle proofs, transcript data, and proof encodings.

use thiserror::Error;

/// Error type returned by fallible Obscura APIs.
///
/// Each variant separates structural failure from verification failure so
/// callers can distinguish malformed input, empty authorization sets, and
/// failed cryptographic checks. The enum does not carry secret key material.
/// Callers should avoid reflecting detailed error strings to untrusted peers
/// when protocol behavior must remain uniform.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// The Merkle tree contains no leaves.
    #[error(
        "Merkle tree error: tree is empty — at least one leaf must be inserted before computing the root"
    )]
    EmptyTree,

    /// The requested leaf index is out of bounds.
    #[error(
        "Merkle tree error: invalid leaf index {index} — tree contains only {total_leaves} leaves"
    )]
    InvalidLeafIndex { index: usize, total_leaves: usize },

    /// Internal failure during tree construction.
    #[error("Merkle tree error: tree construction failure — {reason}")]
    TreeConstructionFailure { reason: String },

    /// The prover could not generate a valid ZK proof.
    #[error("Proof generation error: failed to generate lattice ZK proof — {reason}")]
    ProofGenerationFailure { reason: String },

    /// The Merkle inclusion witness is malformed.
    #[error(
        "Proof error: invalid Merkle witness — the sibling path does not reconstruct the claimed root"
    )]
    InvalidWitness,

    /// The commitment does not match the expected hash.
    #[error(
        "Proof error: commitment mismatch — computed commitment does not match the leaf in the Merkle tree"
    )]
    CommitmentMismatch,

    /// The ZK proof failed lattice-based verification.
    #[error("Verification error: invalid lattice ZK proof — algebraic relation check failed")]
    InvalidProof,

    /// The Merkle root embedded in the proof does not match.
    #[error(
        "Verification error: Merkle root mismatch — proof root does not match the expected anonymity set root"
    )]
    RootMismatch,

    /// The server-issued challenge scope is invalid.
    #[error("Verification error: challenge scope validation failed")]
    ChallengeFailure,

    /// The response vector norm exceeds the rejection bound.
    #[error("Verification error: response norm bound exceeded — ‖z‖∞ ≥ γ₁ - β")]
    NormBoundExceeded,

    /// Proof serialization or deserialization failed.
    #[error("Serialization error: {reason}")]
    SerializationError { reason: String },

    /// A low-level cryptographic operation failed.
    #[error("Cryptographic error: {reason}")]
    CryptoError { reason: String },
}
