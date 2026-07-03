//! High-level API for Obscura credential authorization.
//!
//! This module connects key generation, Merkle membership, proof generation,
//! verification, and JSON proof serialization. It is designed to reject
//! malformed proof data without panicking and to expose a compact API for
//! applications. Verifier entry points require an authenticated Merkle root
//! bound to the expected parameter digest.
use std::fmt;

use rand::{CryptoRng, RngCore};

use crate::error::ProtocolError;
use crate::mlwe::{self, MlweKeyPair, MlweParams};
use crate::poly::PolyVec;
use crate::tree::MerkleProof;
use crate::zk_auth::{self, AuthProof};

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

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

/// Authenticated authorization root bound to a parameter set.
///
/// This wrapper marks the boundary where an application has authenticated the
/// Merkle root and parameter digest, for example by pinning, signing, or
/// loading them from a trusted registry. Raw `[u8; 32]` roots cannot be passed
/// directly to [`Verifier::verify_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRoot {
    root: [u8; 32],
    params_digest: [u8; 32],
}

impl AuthenticatedRoot {
    /// Marks `root` as trusted for `params`.
    ///
    /// # Security
    ///
    /// Call this only after the application has authenticated the root and the
    /// parameter source. This constructor records that trust decision; it does
    /// not establish trust by itself.
    #[must_use]
    pub fn from_trusted_source(root: [u8; 32], params: &MlweParams) -> Self {
        Self {
            root,
            params_digest: params.authentication_digest(),
        }
    }

    /// Returns the authenticated Merkle root bytes.
    #[must_use]
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Returns the parameter digest bound to this root.
    #[must_use]
    pub fn params_digest(&self) -> &[u8; 32] {
        &self.params_digest
    }

    fn matches_params(&self, params: &MlweParams) -> bool {
        ct_eq_32(&self.params_digest, &params.authentication_digest())
    }
}

/// In-memory registry for roots that have already passed application trust policy.
#[derive(Debug, Clone, Default)]
pub struct RootRegistry {
    roots: Vec<AuthenticatedRoot>,
}

impl RootRegistry {
    /// Creates an empty root registry.
    #[must_use]
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Registers a root after the application authenticates it for `params`.
    pub fn register_trusted_root(
        &mut self,
        root: [u8; 32],
        params: &MlweParams,
    ) -> AuthenticatedRoot {
        let authenticated = AuthenticatedRoot::from_trusted_source(root, params);
        self.roots.push(authenticated.clone());
        authenticated
    }

    /// Returns an authenticated wrapper only if the root is already registered.
    #[must_use]
    pub fn authenticate(&self, root: &[u8; 32], params: &MlweParams) -> Option<AuthenticatedRoot> {
        let digest = params.authentication_digest();
        self.roots
            .iter()
            .find(|entry| ct_eq_32(entry.root(), root) && ct_eq_32(entry.params_digest(), &digest))
            .cloned()
    }
}

/// Public inputs that bind a proof to a root, scope, and nullifier.
///
/// These values define the verifier's statement: membership in the
/// authorization set identified by `authenticated_root`, under the session or
/// application context in `scope`, with the expected linkability tag
/// `nullifier`. The root must be wrapped in [`AuthenticatedRoot`] so that raw
/// unauthenticated byte arrays cannot accidentally reach the verifier API.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    /// The authenticated authorization root and parameter digest.
    pub authenticated_root: AuthenticatedRoot,
    /// The session-specific challenge scope (arbitrary bytes).
    pub scope: Vec<u8>,
    /// The nullifier: SHAKE-256("NUL_DOM" ∥ s ∥ scope).
    pub nullifier: [u8; 32],
}

impl PublicInputs {
    /// Constructs verifier public inputs from an authenticated root wrapper.
    #[must_use]
    pub fn new_authenticated(
        authenticated_root: AuthenticatedRoot,
        scope: Vec<u8>,
        nullifier: [u8; 32],
    ) -> Self {
        Self {
            authenticated_root,
            scope,
            nullifier,
        }
    }

    /// Returns the authenticated Merkle root bytes.
    #[must_use]
    pub fn merkle_root(&self) -> &[u8; 32] {
        self.authenticated_root.root()
    }
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
/// the key pair's commitment under the authenticated root.
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
    /// `public_inputs.authenticated_root`.
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
            public_inputs.merkle_root(),
            &public_inputs.nullifier,
            &public_inputs.scope,
            rng,
        )
    }
}

/// Verifier facade for credential authorization proofs.
///
/// The type has no state; it groups proof verification against caller-supplied
/// parameters and authenticated public inputs. It rejects malformed serialized
/// proof structure with `Ok(false)` through the lower-level verifier.
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
    /// `public_inputs.authenticated_root` must come from a trusted source, and
    /// `params` must be the parameter set used by the prover.
    pub fn verify_proof(
        params: &MlweParams,
        proof: &AuthProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, ProtocolError> {
        if !public_inputs.authenticated_root.matches_params(params) {
            return Ok(false);
        }

        zk_auth::verify(
            params,
            proof,
            public_inputs.merkle_root(),
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
/// Serialized proofs are public verification artifacts. They carry a public
/// nullifier for replay detection and an encrypted witness bundle for verifier
/// checks; the public key and Merkle path are not plaintext proof fields.
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
        let authenticated_root = AuthenticatedRoot::from_trusted_source(root, &params);
        let public_inputs =
            PublicInputs::new_authenticated(authenticated_root, scope.clone(), nullifier);

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
        let authenticated_root = AuthenticatedRoot::from_trusted_source(root, &params);
        let public_inputs =
            PublicInputs::new_authenticated(authenticated_root, scope.clone(), nullifier);

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
        let authenticated_root = AuthenticatedRoot::from_trusted_source(root, &params);
        let public_inputs = PublicInputs::new_authenticated(authenticated_root, scope, nullifier);

        let proof = Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
            .unwrap();

        let authenticated_root = AuthenticatedRoot::from_trusted_source(root, &params);
        let wrong_inputs =
            PublicInputs::new_authenticated(authenticated_root, b"wrong_scope".to_vec(), nullifier);

        let valid = Verifier::verify_proof(&params, &proof, &wrong_inputs).unwrap();
        assert!(!valid, "Wrong scope must fail verification");
    }

    #[test]
    fn test_unregistered_parameter_root_pair_rejected() {
        let mut rng = StdRng::seed_from_u64(45);
        let params = MlweParams::generate(&mut rng);
        let other_params = MlweParams::generate(&mut rng);

        let mut tree = MerkleTree::new();
        let user = KeyPair::generate(&params, &mut rng);
        let user_idx = tree.insert(user.commitment()).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(user_idx).unwrap();

        let scope = b"parameter_mismatch".to_vec();
        let nullifier = user.nullifier(&scope);
        let public_inputs = PublicInputs::new_authenticated(
            AuthenticatedRoot::from_trusted_source(root, &params),
            scope.clone(),
            nullifier,
        );
        let proof = Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)
            .unwrap();

        let wrong_inputs = PublicInputs::new_authenticated(
            AuthenticatedRoot::from_trusted_source(root, &other_params),
            scope,
            nullifier,
        );
        let valid = Verifier::verify_proof(&params, &proof, &wrong_inputs).unwrap();
        assert!(!valid, "Parameter/root mismatch must fail verification");
    }
}
