//! High-level API for Obscura credential authorization.
//!
//! This module connects key generation, Merkle membership, proof generation,
//! verification, and JSON proof serialization. It is designed to reject
//! malformed proof data without panicking and to expose a compact API for
//! applications. It does not authenticate Merkle roots, choose deployment
//! parameter policy, or remove timing side channels in the arithmetic layer.
use std::fmt;

use rand::{CryptoRng, RngCore};

use crate::error::ProtocolError;
use crate::mlwe::{self, MlweKeyPair, MlweParams};
use crate::poly::PolyVec;
use crate::tree::MerkleProof;
use crate::zk_auth::{self, AuthProof};

/// A credential key pair for the protocol.
///
/// The key pair carries the secret witness used by the prover and the public
/// key committed into the authorization Merkle tree. Its debug output redacts
/// the secret key. Callers must keep the key bound to the parameters used at
/// generation time and must not serialize the secret witness.
pub struct KeyPair {
    /// The underlying MLWE key pair.
    pub(crate) inner: MlweKeyPair,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.inner.public_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// Public inputs that bind a proof to a root, scope, and nullifier.
///
/// These values define the verifier's statement: membership in the
/// authorization set identified by `merkle_root`, under the session or
/// application context in `scope`, with the expected linkability tag
/// `nullifier`. Callers are responsible for authenticating the Merkle root and
/// choosing scopes that prevent unintended replay or cross-context linkage.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    /// The Merkle root of the anonymity set (32-byte SHAKE-256 hash).
    pub merkle_root: [u8; 32],
    /// The session-specific challenge scope (arbitrary bytes).
    pub scope: Vec<u8>,
    /// The nullifier: SHAKE-256("NUL_DOM" ∥ s ∥ scope).
    pub nullifier: [u8; 32],
}

impl KeyPair {
    /// Generates a new credential key pair under the supplied parameters.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    ///
    /// # Security
    ///
    /// The returned key pair is bound to `params`; proofs produced under other
    /// parameters will not verify.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(params: &MlweParams, rng: &mut R) -> Self {
        KeyPair {
            inner: mlwe::keygen(params, rng),
        }
    }

    /// Returns the public key vector for this credential.
    ///
    /// # Security
    ///
    /// The public key is safe to commit into an authorization set, but it is a
    /// stable identifier for this key pair.
    pub fn public_key(&self) -> &PolyVec {
        self.inner.public_key()
    }

    /// Computes the credential commitment for this key pair.
    ///
    /// # Security
    ///
    /// The commitment is deterministic and should be inserted into the Merkle
    /// authorization set that verifiers trust.
    pub fn commitment(&self) -> [u8; 32] {
        self.inner.commitment()
    }

    /// Derives the nullifier for a given scope.
    ///
    /// # Security
    ///
    /// The same key and scope produce the same nullifier. The scope should be
    /// unique to the verifier context where replay or double-use detection is
    /// required.
    pub fn nullifier(&self, scope: &[u8]) -> [u8; 32] {
        self.inner.nullifier(scope)
    }
}

/// Prover facade for credential membership proofs.
///
/// The type has no state; it groups proof-generation APIs around the witness
/// in [`KeyPair`]. It enforces transcript binding through [`PublicInputs`] and
/// delegates arithmetic to [`zk_auth`]. Callers must provide a Merkle proof for
/// the key pair's commitment under the trusted root.
pub struct Prover;

impl Prover {
    /// Generates a lattice-based authorization proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ChallengeFailure`] if the supplied public
    /// nullifier does not match `keypair` and `public_inputs.scope`. Returns
    /// [`ProtocolError::ProofGenerationFailure`] if rejection sampling does not
    /// find a bounded response within the configured attempt limit.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    ///
    /// # Security
    ///
    /// `merkle_proof` must prove membership of `keypair.commitment()` under
    /// `public_inputs.merkle_root`; this function does not verify the path
    /// before constructing the proof.
    pub fn generate_proof<R: RngCore + CryptoRng + ?Sized>(
        params: &MlweParams,
        keypair: &KeyPair,
        merkle_proof: &MerkleProof,
        public_inputs: &PublicInputs,
        rng: &mut R,
    ) -> Result<AuthProof, ProtocolError> {
        zk_auth::prove(
            params,
            &keypair.inner,
            merkle_proof,
            &public_inputs.merkle_root,
            &public_inputs.nullifier,
            &public_inputs.scope,
            rng,
        )
    }
}

/// Verifier facade for credential authorization proofs.
///
/// The type has no state; it groups proof verification against caller-supplied
/// parameters and public inputs. It rejects malformed serialized proof
/// structure with `Ok(false)` through the lower-level verifier. Callers must
/// authenticate the root and parameter set before accepting a positive result.
pub struct Verifier;

impl Verifier {
    /// Verifies a lattice-based authorization proof.
    ///
    /// Returns `Ok(true)` if all checks pass and `Ok(false)` if the proof fails
    /// a structural, transcript, algebraic, or Merkle-membership check.
    ///
    /// # Errors
    ///
    /// This function currently returns verification failures as `Ok(false)`.
    /// It reserves [`ProtocolError`] for future structural failures that
    /// prevent verification from running.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural
    /// checks are performed before any arithmetic. Malformed input is
    /// rejected with `Ok(false)` rather than panicking.
    ///
    /// # Security
    ///
    /// `public_inputs.merkle_root` must come from a trusted source, and
    /// `params` must be the parameter set used by the prover.
    pub fn verify_proof(
        params: &MlweParams,
        proof: &AuthProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, ProtocolError> {
        zk_auth::verify(
            params,
            proof,
            &public_inputs.merkle_root,
            &public_inputs.nullifier,
            &public_inputs.scope,
        )
    }
}

/// Serializes an authorization proof to JSON bytes.
///
/// # Errors
///
/// Returns [`ProtocolError::SerializationError`] if `serde_json` cannot encode
/// the proof.
///
/// # Security
///
/// Serialized proofs are public verification artifacts, but they may be
/// linkable through their nullifier and Merkle path.
pub fn serialize_proof(proof: &AuthProof) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(proof).map_err(|e| ProtocolError::SerializationError {
        reason: e.to_string(),
    })
}

/// Deserializes an authorization proof from JSON bytes.
///
/// # Errors
///
/// Returns [`ProtocolError::SerializationError`] if the byte slice is not a
/// valid proof encoding or contains invalid polynomial structure.
///
/// # Untrusted Input
///
/// This function accepts data from untrusted sources. Structural checks are
/// performed by serde and nested deserializers before an [`AuthProof`] is
/// returned.
///
/// # Security
///
/// Deserialization alone does not validate the proof. Call
/// [`Verifier::verify_proof`] before accepting the result.
pub fn deserialize_proof(bytes: &[u8]) -> Result<AuthProof, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|e| ProtocolError::SerializationError {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleTree;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_full_lattice_zk_flow() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(42);

        let params = MlweParams::generate(&mut rng);

        let mut tree = MerkleTree::new();
        for _ in 0..3 {
            let dummy = KeyPair::generate(&params, &mut rng);
            tree.insert(dummy.commitment()).unwrap();
        }

        let user = KeyPair::generate(&params, &mut rng);
        let user_idx = tree.insert(user.commitment()).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(user_idx).unwrap();

        let scope = b"session_challenge_xyz".to_vec();
        let nullifier = user.nullifier(&scope);
        let public_inputs = PublicInputs {
            merkle_root: root,
            scope: scope.clone(),
            nullifier,
        };

        let proof = Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
            .unwrap();

        let valid = Verifier::verify_proof(&params, &proof, &public_inputs).unwrap();
        assert!(valid, "Valid proof must pass verification");
    }

    #[test]
    fn test_serialization_roundtrip() {
        // Seeded for test determinism. Production code must use OsRng.
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

        let proof = Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
            .unwrap();

        let bytes = serialize_proof(&proof).unwrap();
        let recovered = deserialize_proof(&bytes).unwrap();

        let valid = Verifier::verify_proof(&params, &recovered, &public_inputs).unwrap();
        assert!(valid, "Deserialized proof must still verify");
    }

    #[test]
    fn test_wrong_scope_rejected() {
        // Seeded for test determinism. Production code must use OsRng.
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

        let proof = Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
            .unwrap();

        let wrong_inputs = PublicInputs {
            merkle_root: root,
            scope: b"wrong_scope".to_vec(),
            nullifier,
        };

        let valid = Verifier::verify_proof(&params, &proof, &wrong_inputs).unwrap();
        assert!(!valid, "Wrong scope must fail verification");
    }
}
