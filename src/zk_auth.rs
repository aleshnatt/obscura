//! Fiat-Shamir-style authorization proofs over Module-LWE key material.
//!
//! This module binds a credential public key, a scope-bound nullifier, and a
//! Merkle membership proof into one verification statement. It is designed to
//! reject malformed proof objects without panicking and to resist a
//! computationally bounded prover that does not know the committed short
//! secret. It does not provide a formally audited zero-knowledge guarantee, and
//! timing side channels exist on norm checks and polynomial arithmetic.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::error::ProtocolError;
use crate::mlwe::{commitment_hash, sample_challenge, MlweKeyPair, MlweParams};
use crate::poly::{Poly, PolyVec, BETA, ETA, GAMMA1, K, TAU};
use crate::tree::MerkleProof;

/// Maximum number of rejection sampling attempts before hard failure.
const MAX_ATTEMPTS: u32 = 1000;

/// Lattice-based authorization proof for one credential and scope.
///
/// The proof carries the public key, bounded response, Fiat-Shamir challenge,
/// nullifier, Merkle path, and commitment transcript needed by the verifier.
/// It enforces no trust by construction after deserialization; callers must run
/// verification against trusted public inputs before accepting it. The
/// nullifier and Merkle path are public and may be linkable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof {
    /// Public key vector whose commitment is proven in the Merkle tree.
    pub public_key: PolyVec,
    /// Response vector z = y + c·s mod q ∈ R_q^k.
    pub z: PolyVec,
    /// Challenge polynomial c ∈ R_q with τ non-zero ±1 coefficients.
    pub c: Poly,
    /// Nullifier: SHAKE-256("NUL_DOM" ∥ s ∥ scope), 32 bytes.
    pub nullifier: [u8; 32],
    /// Merkle inclusion proof for the public key commitment.
    pub merkle_path: MerkleProof,
    /// The commitment hash of the prover's public key (Merkle leaf).
    pub commitment_hash: [u8; 32],
    /// Serialized commitment w = A · y mod q (for challenge reconstruction).
    pub w_bytes: Vec<u8>,
}

/// Derives the nullifier for a secret key and authorization scope.
///
/// # Security
///
/// The same secret key and scope always produce the same nullifier. Callers
/// must choose scopes that match their replay and linkability requirements, and
/// must not reuse scopes across contexts that should remain unlinkable.
pub fn derive_nullifier(secret_key: &PolyVec, scope: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"NUL_DOM");
    hasher.update(&secret_key.to_bytes());
    hasher.update(scope);
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

/// Compute the challenge hash seed from the proof transcript.
///
/// seed = SHAKE-256("ZK_DOM" ∥ root ∥ nullifier ∥ w_bytes ∥ scope).
///
/// This seed is then passed to `sample_challenge()` to produce the
/// challenge polynomial c.
fn challenge_hash_seed(
    root: &[u8; 32],
    nullifier: &[u8; 32],
    w_bytes: &[u8],
    scope: &[u8],
) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(b"ZK_DOM");
    hasher.update(root);
    hasher.update(nullifier);
    hasher.update(w_bytes);
    hasher.update(scope);
    let mut seed = vec![0u8; 64];
    hasher.finalize_xof().read(&mut seed);
    seed
}

/// Generates an authorization proof for a committed credential.
///
/// The proof binds the key pair, Merkle inclusion path, trusted root, expected
/// nullifier, and scope into one transcript.
///
/// # Errors
///
/// Returns [`ProtocolError::ChallengeFailure`] if `expected_nullifier` does not
/// match the nullifier derived from `keypair` and `scope`. Returns
/// [`ProtocolError::ProofGenerationFailure`] if rejection sampling fails to
/// find a response below the norm bound within the configured attempt limit.
///
/// # Randomness
///
/// The `rng` parameter must be a cryptographically secure pseudorandom
/// number generator. Passing a weak or deterministic RNG breaks the
/// security of the output.
///
/// # Security
///
/// `root` must be the trusted authorization root for `merkle_proof`, and
/// `scope` must be chosen by the verifier or application context. This function
/// does not validate Merkle membership before returning a proof object.
pub fn prove<R: RngCore + CryptoRng + ?Sized>(
    params: &MlweParams,
    keypair: &MlweKeyPair,
    merkle_proof: &MerkleProof,
    root: &[u8; 32],
    expected_nullifier: &[u8; 32],
    scope: &[u8],
    rng: &mut R,
) -> Result<AuthProof, ProtocolError> {
    let nullifier = derive_nullifier(&keypair.secret_key, scope);
    if &nullifier != expected_nullifier {
        return Err(ProtocolError::ChallengeFailure);
    }

    let credential_commitment = commitment_hash(&keypair.public_key);

    for _attempt in 0..MAX_ATTEMPTS {
        let masking_vector = PolyVec::sample_masking(rng);

        let transcript_commitment = params.matrix_a.mul_vec(&masking_vector);
        let w_bytes = transcript_commitment.to_bytes();

        let seed = challenge_hash_seed(root, &nullifier, &w_bytes, scope);
        let challenge = sample_challenge(&seed);

        let challenge_secret = keypair.secret_key.scalar_mul(&challenge);
        let response = masking_vector.add(&challenge_secret);

        let bound = GAMMA1 - BETA;
        if response.infinity_norm() >= bound {
            continue;
        }

        return Ok(AuthProof {
            public_key: keypair.public_key.clone(),
            z: response,
            c: challenge,
            nullifier,
            merkle_path: merkle_proof.clone(),
            commitment_hash: credential_commitment,
            w_bytes,
        });
    }

    Err(ProtocolError::ProofGenerationFailure {
        reason: format!(
            "Rejection sampling failed after {} attempts (highly unlikely — check parameters)",
            MAX_ATTEMPTS
        ),
    })
}

/// Verifies an authorization proof against public inputs.
///
/// Returns `Ok(true)` if the proof is valid and `Ok(false)` if any structural,
/// transcript, algebraic, nullifier, or Merkle-membership check fails.
///
/// # Errors
///
/// This function currently returns verification failures as `Ok(false)` and
/// reserves [`ProtocolError`] for future structural failures that prevent
/// verification from running.
///
/// # Untrusted Input
///
/// This function accepts data from untrusted sources. All structural
/// checks are performed before any arithmetic. Malformed input is
/// rejected with `Ok(false)` rather than panicking.
///
/// # Timing
///
/// This function is not constant-time with respect to its input.
/// Callers on secret data accept a timing side-channel risk.
///
/// # Security
///
/// `root` must be obtained from a trusted source, `expected_nullifier` must be
/// computed for the intended scope, and `params` must match the prover's
/// parameter set. An adversary-controlled root can make membership statements
/// refer to an adversary-chosen authorization set.
pub fn verify(
    params: &MlweParams,
    proof: &AuthProof,
    root: &[u8; 32],
    expected_nullifier: &[u8; 32],
    scope: &[u8],
) -> Result<bool, ProtocolError> {
    if proof.public_key.polys.len() != K {
        return Ok(false);
    }
    if proof.z.polys.len() != K {
        return Ok(false);
    }

    if proof.nullifier != *expected_nullifier {
        return Ok(false);
    }

    let bound = GAMMA1 - BETA;
    if proof.z.infinity_norm() >= bound {
        return Ok(false);
    }

    let transcript_commitment = match PolyVec::from_bytes(&proof.w_bytes) {
        Some(transcript_commitment) => transcript_commitment,
        None => return Ok(false),
    };

    let seed = challenge_hash_seed(root, &proof.nullifier, &proof.w_bytes, scope);
    let expected_challenge = sample_challenge(&seed);
    if expected_challenge != proof.c {
        return Ok(false);
    }

    // In the honest case:
    //   z = y + c·s
    //   A·z = A·(y + c·s) = A·y + c·(A·s) = w - c·e + c·(b - e) + c·e
    //       = w + c·b - c·e
    //
    // So: diff = A·z - w - c·b = -c·e
    // Since ||e||_inf <= eta and ||c||_1 = tau, every coefficient of c*e
    // is a signed sum of at most tau error coefficients, each bounded by eta.
    let az = params.matrix_a.mul_vec(&proof.z);
    let cb = proof.public_key.scalar_mul(&proof.c);
    let diff = az.sub(&transcript_commitment).sub(&cb);

    let diff_bound = (TAU as i64) * ETA + 1;
    if diff.infinity_norm() >= diff_bound {
        return Ok(false);
    }

    let expected_commitment = commitment_hash(&proof.public_key);
    if expected_commitment != proof.commitment_hash {
        return Ok(false);
    }

    if proof.merkle_path.leaf != proof.commitment_hash {
        return Ok(false);
    }
    if proof.merkle_path.root != *root {
        return Ok(false);
    }
    if !crate::tree::MerkleTree::verify_inclusion_proof(&proof.merkle_path) {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlwe::{keygen, MlweParams};
    use crate::tree::MerkleTree;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn setup_test_scenario(
        seed: u64,
    ) -> (MlweParams, MlweKeyPair, MerkleTree, [u8; 32], MerkleProof) {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(seed);
        let params = MlweParams::generate(&mut rng);

        let mut tree = MerkleTree::new();
        for _ in 0..3 {
            let dummy_kp = keygen(&params, &mut rng);
            let comm = commitment_hash(&dummy_kp.public_key);
            tree.insert(comm).unwrap();
        }

        let user_kp = keygen(&params, &mut rng);
        let user_comm = commitment_hash(&user_kp.public_key);
        let user_idx = tree.insert(user_comm).unwrap();
        let root = tree.root().unwrap();
        let merkle_proof = tree.generate_inclusion_proof(user_idx).unwrap();

        (params, user_kp, tree, root, merkle_proof)
    }

    #[test]
    fn test_prove_and_verify_roundtrip() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(100);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(200);
        let scope = b"session_challenge_42";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(valid, "Valid proof must pass verification");
    }

    #[test]
    fn test_wrong_scope_rejected() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(101);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(201);
        let scope = b"correct_scope";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        let valid = verify(&params, &proof, &root, &nullifier, b"wrong_scope")
            .expect("Verification must run");
        assert!(!valid, "Wrong scope must fail verification");
    }

    #[test]
    fn test_wrong_root_rejected() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(102);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(202);
        let scope = b"test_scope";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        let wrong_root = [0xFFu8; 32]; // simulate an untrusted root substitution
        let valid =
            verify(&params, &proof, &wrong_root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Wrong root must fail verification");
    }

    #[test]
    fn test_wrong_public_key_rejected() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(103);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(203);
        let scope = b"test_scope";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        let wrong_kp = keygen(&params, &mut rng);
        let mut proof = proof;
        proof.public_key = wrong_kp.public_key().clone(); // simulate public-key substitution
        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Wrong public key must fail verification");
    }

    #[test]
    fn test_nullifier_determinism() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(104);
        let params = MlweParams::generate(&mut rng);
        let kp = keygen(&params, &mut rng);
        let scope = b"determinism_test";

        let n1 = derive_nullifier(&kp.secret_key, scope);
        let n2 = derive_nullifier(&kp.secret_key, scope);
        assert_eq!(n1, n2, "Same key + scope must produce same nullifier");
    }

    #[test]
    fn test_nullifier_uniqueness() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(105);
        let params = MlweParams::generate(&mut rng);
        let kp = keygen(&params, &mut rng);

        let n1 = derive_nullifier(&kp.secret_key, b"scope_A");
        let n2 = derive_nullifier(&kp.secret_key, b"scope_B");
        assert_ne!(n1, n2, "Different scopes must produce different nullifiers");
    }

    #[test]
    fn test_tampered_z_rejected() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(106);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(206);
        let scope = b"tamper_test";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let mut proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        proof.z.polys[0].coeffs[0] = (proof.z.polys[0].coeffs[0] + 1) % crate::poly::Q; // simulate response tampering

        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Tampered z must fail verification");
    }

    #[test]
    fn test_verify_rejects_wrong_pubkey_len() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(107);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(207);
        let scope = b"wrong_pubkey_len";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let mut proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        proof.public_key.polys.push(Poly::zero()); // simulate a malformed public-key vector

        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Malformed public key length must be rejected");
    }

    #[test]
    fn test_verify_rejects_wrong_z_len() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(108);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(208);
        let scope = b"wrong_z_len";

        let nullifier = derive_nullifier(&user_kp.secret_key, scope);
        let mut proof = prove(
            &params,
            &user_kp,
            &merkle_proof,
            &root,
            &nullifier,
            scope,
            &mut rng,
        )
        .expect("Proof generation should succeed");

        proof.z.polys.truncate(0); // simulate a truncated response vector

        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Malformed response length must be rejected");
    }
}
