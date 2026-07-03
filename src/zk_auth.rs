//! Fiat-Shamir-style authorization proofs over Module-LWE key material.
//!
//! This module binds a credential commitment, a scope-bound nullifier, and an
//! encrypted Merkle witness bundle into one verification statement. It is
//! designed to reject malformed proof objects without panicking and to resist a
//! computationally bounded prover that does not know the committed short
//! secret. It does not provide a formally audited hidden-member proof system;
//! the verifier decrypts the witness bundle during verification.

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
/// The proof carries the bounded response, Fiat-Shamir challenge, nullifier,
/// credential commitment, transcript commitment, and an encrypted witness
/// bundle. The public key and Merkle path are not plaintext proof fields.
/// Callers must run verification against authenticated public inputs before
/// accepting it. The nullifier remains public by design for scope-local replay
/// detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof {
    /// Response vector z = y + c·s mod q ∈ R_q^k.
    pub z: PolyVec,
    /// Challenge polynomial c ∈ R_q with τ non-zero ±1 coefficients.
    pub c: Poly,
    /// Nullifier: SHAKE-256("NUL_DOM" ∥ s ∥ scope), 32 bytes.
    pub nullifier: [u8; 32],
    /// The commitment hash of the prover's public key (Merkle leaf).
    pub commitment_hash: [u8; 32],
    /// Serialized commitment w = A · y mod q (for challenge reconstruction).
    pub w_bytes: Vec<u8>,
    /// Root/scope/nullifier-bound encrypted public key and Merkle path.
    pub witness_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HiddenWitness {
    public_key: PolyVec,
    merkle_path: MerkleProof,
}

struct WitnessContext<'a> {
    root: &'a [u8; 32],
    nullifier: &'a [u8; 32],
    commitment_hash: &'a [u8; 32],
    w_bytes: &'a [u8],
    c: &'a Poly,
    z: &'a PolyVec,
    scope: &'a [u8],
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

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn ct_eq_poly(a: &Poly, b: &Poly) -> bool {
    let mut diff = 0i64;
    for i in 0..crate::poly::N {
        diff |= a.coeffs[i] ^ b.coeffs[i];
    }
    diff == 0
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

fn witness_keystream_seed(ctx: &WitnessContext<'_>) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(b"WIT_ENC");
    hasher.update(ctx.root);
    hasher.update(ctx.nullifier);
    hasher.update(ctx.commitment_hash);
    hasher.update(ctx.w_bytes);
    hasher.update(&ctx.c.to_bytes());
    hasher.update(&ctx.z.to_bytes());
    hasher.update(ctx.scope);
    let mut seed = vec![0u8; 64];
    hasher.finalize_xof().read(&mut seed);
    seed
}

fn apply_witness_stream(data: &[u8], seed: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();
    let mut stream = vec![0u8; data.len()];
    xof.read(&mut stream);
    data.iter()
        .zip(stream)
        .map(|(byte, mask)| byte ^ mask)
        .collect()
}

fn encrypt_witness(
    witness: &HiddenWitness,
    ctx: &WitnessContext<'_>,
) -> Result<Vec<u8>, ProtocolError> {
    let encoded = serde_json::to_vec(witness).map_err(|e| ProtocolError::SerializationError {
        reason: e.to_string(),
    })?;
    let seed = witness_keystream_seed(ctx);
    Ok(apply_witness_stream(&encoded, &seed))
}

fn decrypt_witness(
    proof: &AuthProof,
    root: &[u8; 32],
    scope: &[u8],
) -> Result<HiddenWitness, ProtocolError> {
    let ctx = WitnessContext {
        root,
        nullifier: &proof.nullifier,
        commitment_hash: &proof.commitment_hash,
        w_bytes: &proof.w_bytes,
        c: &proof.c,
        z: &proof.z,
        scope,
    };
    let seed = witness_keystream_seed(&ctx);
    let encoded = apply_witness_stream(&proof.witness_ciphertext, &seed);
    serde_json::from_slice(&encoded).map_err(|e| ProtocolError::SerializationError {
        reason: e.to_string(),
    })
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
    if !ct_eq_32(&nullifier, expected_nullifier) {
        return Err(ProtocolError::ChallengeFailure);
    }

    let credential_commitment = commitment_hash(&keypair.public_key);
    if !ct_eq_32(&merkle_proof.leaf, &credential_commitment)
        || !ct_eq_32(&merkle_proof.root, root)
        || !crate::tree::MerkleTree::verify_inclusion_proof(merkle_proof)
    {
        return Err(ProtocolError::ChallengeFailure);
    }

    for _attempt in 0..MAX_ATTEMPTS {
        let masking_vector = PolyVec::sample_masking(rng);

        let transcript_commitment = params.matrix_a.mul_vec(&masking_vector);
        let w_bytes = transcript_commitment.to_bytes();

        let seed = challenge_hash_seed(root, &nullifier, &w_bytes, scope);
        let challenge = sample_challenge(&seed);

        let challenge_secret = keypair.secret_key.scalar_mul(&challenge);
        let response = masking_vector.add(&challenge_secret);

        let bound = GAMMA1 - BETA;
        if !response.infinity_norm_lt(bound) {
            continue;
        }

        let witness = HiddenWitness {
            public_key: keypair.public_key.clone(),
            merkle_path: merkle_proof.clone(),
        };
        let witness_context = WitnessContext {
            root,
            nullifier: &nullifier,
            commitment_hash: &credential_commitment,
            w_bytes: &w_bytes,
            c: &challenge,
            z: &response,
            scope,
        };
        let witness_ciphertext = encrypt_witness(&witness, &witness_context)?;

        return Ok(AuthProof {
            z: response,
            c: challenge,
            nullifier,
            commitment_hash: credential_commitment,
            w_bytes,
            witness_ciphertext,
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
/// Norm and fixed-size transcript comparisons scan their complete inputs
/// without early exit. Structural parsing can still fail early on malformed
/// public input.
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
    if proof.z.polys.len() != K {
        return Ok(false);
    }

    let mut valid = ct_eq_32(&proof.nullifier, expected_nullifier);

    let bound = GAMMA1 - BETA;
    valid &= proof.z.infinity_norm_lt(bound);

    let transcript_commitment = match PolyVec::from_bytes(&proof.w_bytes) {
        Some(transcript_commitment) => transcript_commitment,
        None => return Ok(false),
    };

    let seed = challenge_hash_seed(root, &proof.nullifier, &proof.w_bytes, scope);
    let expected_challenge = sample_challenge(&seed);
    valid &= ct_eq_poly(&expected_challenge, &proof.c);

    let witness = match decrypt_witness(proof, root, scope) {
        Ok(witness) => witness,
        Err(_) => return Ok(false),
    };

    if witness.public_key.polys.len() != K {
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
    let cb = witness.public_key.scalar_mul(&proof.c);
    let diff = az.sub(&transcript_commitment).sub(&cb);

    let diff_bound = (TAU as i64) * ETA + 1;
    valid &= diff.infinity_norm_lt(diff_bound);

    let expected_commitment = commitment_hash(&witness.public_key);
    valid &= ct_eq_32(&expected_commitment, &proof.commitment_hash);
    valid &= ct_eq_32(&witness.merkle_path.leaf, &proof.commitment_hash);
    valid &= ct_eq_32(&witness.merkle_path.root, root);
    valid &= crate::tree::MerkleTree::verify_inclusion_proof(&witness.merkle_path);

    Ok(valid)
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
    fn test_tampered_commitment_rejected() {
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

        let mut proof = proof;
        proof.commitment_hash[0] ^= 0x01; // simulate commitment substitution
        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Tampered commitment must fail verification");
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
    fn test_verify_rejects_tampered_witness_ciphertext() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(107);
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(207);
        let scope = b"tampered_witness";

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

        proof.witness_ciphertext[0] ^= 0x01; // simulate encrypted witness tampering

        let valid =
            verify(&params, &proof, &root, &nullifier, scope).expect("Verification must run");
        assert!(!valid, "Tampered encrypted witness must be rejected");
    }

    #[test]
    fn test_serialized_proof_omits_plaintext_member_witness() {
        let (params, user_kp, _tree, root, merkle_proof) = setup_test_scenario(109);
        let mut rng = StdRng::seed_from_u64(209);
        let scope = b"plaintext_witness_check";

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

        let encoded = serde_json::to_string(&proof).unwrap();
        assert!(!encoded.contains("\"public_key\""));
        assert!(!encoded.contains("\"merkle_path\""));
        assert!(encoded.contains("\"witness_ciphertext\""));
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
