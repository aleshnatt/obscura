//! # Obscura Protocol — Lattice-Based ZK Authorization
//!
//! Implements the post-quantum Zero-Knowledge authorization protocol based
//! on the Fiat-Shamir with Aborts paradigm over Module-LWE/Module-SIS.
//!
//! ## Proving Protocol
//!
//! Given a secret key s, public key b = A·s + e, and a Merkle root:
//!
//! 1. Derive nullifier = SHAKE-256("NUL_DOM" ∥ s ∥ scope).
//! 2. Sample masking vector y ← Uniform([-γ₁+1, γ₁])^{k·n}.
//! 3. Compute commitment w = A · y mod q.
//! 4. Compute challenge c = ChallengeHash(root, nullifier, w, scope).
//! 5. Compute response z = y + c · s mod q.
//! 6. Rejection sampling: check ‖z‖∞ < γ₁ - β; abort if not.
//! 7. Output pi = (public_key, z, c, nullifier, merkle_path, commitment_hash, w_bytes).
//!
//! ## Verification Protocol
//!
//! 1. Check ‖z‖∞ < γ₁ - β.
//! 2. Reconstruct w from w_bytes.
//! 3. Recompute c' from (root, nullifier, w, scope) and check c' = c.
//! 4. Verify A·z - w - c·b has small norm.
//! 5. Verify Merkle path from commitment_hash to root.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::error::ProtocolError;
use crate::mlwe::{MlweKeyPair, MlweParams, commitment_hash, sample_challenge};
use crate::poly::{BETA, GAMMA1, N, Poly, PolyVec, TAU};
use crate::tree::MerkleProof;

/// Maximum number of rejection sampling attempts before hard failure.
const MAX_ATTEMPTS: u32 = 1000;

// ─── Proof Structure ─────────────────────────────────────────────────────────

/// A lattice-based ZK authorization proof.
///
/// Contains all data needed for verification:
/// - Public key vector b.
/// - Response vector z (the masked secret).
/// - Challenge polynomial c.
/// - Nullifier (links proof to scope without revealing identity).
/// - Merkle path proving public key membership.
/// - Commitment hash (the leaf value).
/// - Serialized commitment w = A·y for challenge reconstruction.
///
/// Serialized size depends on the Merkle path length and serialization format.
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

// ─── Nullifier Derivation ────────────────────────────────────────────────────

/// Derive the nullifier for a given secret key and scope.
///
/// nullifier = SHAKE-256("NUL_DOM" ∥ serialize(s) ∥ scope), truncated to 32 bytes.
///
/// The nullifier binds the proof to the scope (e.g., a session challenge)
/// without revealing which secret key was used. The same (s, scope) pair
/// always produces the same nullifier, enabling replay detection.
pub fn derive_nullifier(secret_key: &PolyVec, scope: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"NUL_DOM");
    hasher.update(&secret_key.to_bytes());
    hasher.update(scope);
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

// ─── Challenge Hash ──────────────────────────────────────────────────────────

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

// ─── Prove ───────────────────────────────────────────────────────────────────

/// Generate a ZK authorization proof.
///
/// The prover proves knowledge of a short MLWE secret key s whose
/// public key b is committed in a Merkle tree with the given root, without
/// revealing s.
///
/// ## Arguments
///
/// * `params` - MLWE public parameters (matrix A).
/// * `keypair` - The prover's MLWE key pair (s, b).
/// * `merkle_proof` - Merkle inclusion proof for the public key commitment.
/// * `root` - The expected Merkle root (32-byte hash).
/// * `scope` - Session-specific challenge scope (arbitrary bytes).
/// * `rng` - Cryptographic random number generator.
///
/// ## Rejection Sampling
///
/// The protocol uses the Fiat-Shamir with Aborts paradigm: if the
/// response z has ‖z‖∞ ≥ γ₁ - β, the attempt is aborted and
/// restarted with a fresh masking vector. This ensures z does not
/// leak information about s. Expected attempts: ~4-5 per proof.
pub fn prove<R: RngCore + CryptoRng + ?Sized>(
    params: &MlweParams,
    keypair: &MlweKeyPair,
    merkle_proof: &MerkleProof,
    root: &[u8; 32],
    expected_nullifier: &[u8; 32],
    scope: &[u8],
    rng: &mut R,
) -> Result<AuthProof, ProtocolError> {
    // Step 1: Derive nullifier.
    let nullifier = derive_nullifier(&keypair.secret_key, scope);
    if &nullifier != expected_nullifier {
        return Err(ProtocolError::ChallengeFailure);
    }

    // Precompute the commitment hash of the public key.
    let comm_hash = commitment_hash(&keypair.public_key);

    // Rejection sampling loop.
    for _attempt in 0..MAX_ATTEMPTS {
        // Step 2: Sample masking vector y.
        let y = PolyVec::sample_masking(rng);

        // Step 3: Compute commitment w = A · y mod q.
        let w = params.matrix_a.mul_vec(&y);
        let w_bytes = w.to_bytes();

        // Step 4: Compute challenge c.
        let seed = challenge_hash_seed(root, &nullifier, &w_bytes, scope);
        let c = sample_challenge(&seed);

        // Step 5: Compute response z = y + c · s mod q.
        // c · s is computed as: for each component s_i, multiply by c.
        let cs = keypair.secret_key.scalar_mul(&c);
        let z = y.add(&cs);

        // Step 6: Rejection sampling — check ‖z‖∞ < γ₁ - β.
        let bound = GAMMA1 - BETA;
        if z.infinity_norm() >= bound {
            continue; // Abort this attempt, try again.
        }

        // Step 7: Construct proof.
        return Ok(AuthProof {
            public_key: keypair.public_key.clone(),
            z,
            c,
            nullifier,
            merkle_path: merkle_proof.clone(),
            commitment_hash: comm_hash,
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

// ─── Verify ──────────────────────────────────────────────────────────────────

/// Verify a ZK authorization proof.
///
/// ## Verification Steps
///
/// 1. Check ‖z‖∞ < γ₁ - β (response norm bound).
/// 2. Reconstruct w from w_bytes.
/// 3. Recompute challenge c' from (root, nullifier, w, scope) and check c' = c.
/// 4. Compute diff = A·z - w - c·b mod q and check ‖diff‖∞ is small.
/// 5. Verify that commitment_hash matches the leaf in the Merkle path for the root.
///
/// ## Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` if any check fails.
pub fn verify(
    params: &MlweParams,
    proof: &AuthProof,
    root: &[u8; 32],
    expected_nullifier: &[u8; 32],
    scope: &[u8],
) -> Result<bool, ProtocolError> {
    if proof.nullifier != *expected_nullifier {
        return Ok(false);
    }

    // Step 1: Check response norm bound.
    let bound = GAMMA1 - BETA;
    if proof.z.infinity_norm() >= bound {
        return Ok(false);
    }

    // Step 2: Reconstruct w from w_bytes.
    let w = match PolyVec::from_bytes(&proof.w_bytes) {
        Some(w) => w,
        None => return Ok(false),
    };

    // Step 3: Recompute challenge and verify consistency.
    let seed = challenge_hash_seed(root, &proof.nullifier, &proof.w_bytes, scope);
    let c_prime = sample_challenge(&seed);
    if c_prime != proof.c {
        return Ok(false);
    }

    // Step 4: Verify algebraic relation.
    //
    // In the honest case:
    //   z = y + c·s
    //   A·z = A·(y + c·s) = A·y + c·(A·s) = w - c·e + c·(b - e) + c·e
    //       = w + c·b - c·e
    //
    // So: diff = A·z - w - c·b = -c·e
    // Since ‖e‖∞ ≤ η and ‖c‖₁ = τ, ‖c·e‖∞ ≤ τ·η·n (loose bound).
    //
    // We check ‖diff‖∞ < τ · η · n + 1 = 39 · 2 · 256 + 1 = 19,969.
    let az = params.matrix_a.mul_vec(&proof.z);
    let cb = proof.public_key.scalar_mul(&proof.c);
    let diff = az.sub(&w).sub(&cb);

    let diff_bound = (TAU as i64) * 2 * (N as i64) + 1;
    if diff.infinity_norm() >= diff_bound {
        return Ok(false);
    }

    // Step 5: Verify Merkle membership.
    // Check that the commitment hash matches the expected public key commitment.
    let expected_commitment = commitment_hash(&proof.public_key);
    if expected_commitment != proof.commitment_hash {
        return Ok(false);
    }

    // Check that the Merkle path validates from the commitment to the root.
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
    use crate::mlwe::{MlweParams, keygen};
    use crate::tree::MerkleTree;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn setup_test_scenario(
        seed: u64,
    ) -> (MlweParams, MlweKeyPair, MerkleTree, [u8; 32], MerkleProof) {
        let mut rng = StdRng::seed_from_u64(seed);
        let params = MlweParams::generate(&mut rng);

        // Generate some dummy users.
        let mut tree = MerkleTree::new();
        for _ in 0..3 {
            let dummy_kp = keygen(&params, &mut rng);
            let comm = commitment_hash(&dummy_kp.public_key);
            tree.insert(comm).unwrap();
        }

        // Generate the prover's key pair.
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

        // Verify with wrong scope.
        let valid = verify(&params, &proof, &root, &nullifier, b"wrong_scope")
            .expect("Verification must run");
        assert!(!valid, "Wrong scope must fail verification");
    }

    #[test]
    fn test_wrong_root_rejected() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(102);
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

        // Verify with wrong root.
        let wrong_root = [0xFFu8; 32];
        let valid =
            verify(&params, &proof, &wrong_root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Wrong root must fail verification");
    }

    #[test]
    fn test_wrong_public_key_rejected() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(103);
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

        // Tamper with the public key embedded in the proof.
        let wrong_kp = keygen(&params, &mut rng);
        let mut proof = proof;
        proof.public_key = wrong_kp.public_key.clone();
        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Wrong public key must fail verification");
    }

    #[test]
    fn test_nullifier_determinism() {
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

        // Tamper with z.
        proof.z.polys[0].coeffs[0] = (proof.z.polys[0].coeffs[0] + 1) % crate::poly::Q;

        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Tampered z must fail verification");
    }
}
