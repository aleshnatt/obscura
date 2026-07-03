//! Module-LWE parameter and key material for Obscura authorization proofs.
//!
//! The module builds public matrices, short secret vectors, public key vectors,
//! and sparse Fiat-Shamir challenges used by the proof relation. It targets
//! computational adversaries that cannot recover a short secret from the public
//! Module-LWE-style relation. Its concrete security level requires independent
//! parameter review.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::fmt;
use zeroize::ZeroizeOnDrop;

use crate::poly::{Poly, PolyMat, PolyVec, K, N, Q, TAU};

/// Module-LWE public parameters.
///
/// The parameter matrix binds key generation, proof generation, and
/// verification to the same public relation. It carries no secret material, but
/// using different parameters across parties invalidates proof verification.
/// Callers should derive shared parameters from an authenticated public seed
/// when multiple systems must interoperate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlweParams {
    /// The public k × k polynomial matrix A ∈ R_q^{k×k}.
    pub matrix_a: PolyMat,
}

impl MlweParams {
    /// Generates fresh MLWE parameters with a random public matrix.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of generated parameters.
    ///
    /// # Security
    ///
    /// Parameters generated this way are only shared with parties that receive
    /// the full matrix. Use [`MlweParams::from_seed`] when independent parties
    /// must derive the same public parameters.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        MlweParams {
            matrix_a: PolyMat::sample_uniform(rng),
        }
    }

    /// Derives shared MLWE parameters from a public 32-byte seed.
    ///
    /// # Security
    ///
    /// The seed is a public coordination value, not a secret. Callers must
    /// authenticate the seed or matrix source; an adversary-selected parameter
    /// set changes the relation being proven.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(b"obscura-mlwe-params-v1");
        hasher.update(seed);
        let mut xof = hasher.finalize_xof();

        let rows = (0..K)
            .map(|_| {
                let polys = (0..K).map(|_| sample_uniform_from_xof(&mut xof)).collect();
                PolyVec { polys }
            })
            .collect();

        MlweParams {
            matrix_a: PolyMat { rows },
        }
    }

    /// Computes a stable authentication digest for this parameter set.
    ///
    /// # Security
    ///
    /// Applications can pin or sign this digest alongside a Merkle root to
    /// ensure verifiers use the same public matrix as provers. The digest is
    /// not secret and does not make adversary-selected parameters trustworthy
    /// unless the application authenticates it.
    #[must_use]
    pub fn authentication_digest(&self) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(b"PARAM_DOM");
        for row in &self.matrix_a.rows {
            hasher.update(&row.to_bytes());
        }
        let mut output = [0u8; 32];
        hasher.finalize_xof().read(&mut output);
        output
    }
}

fn sample_uniform_from_xof<X: XofReader>(xof: &mut X) -> Poly {
    let mut poly = Poly::zero();
    for coeff in poly.coeffs.iter_mut() {
        loop {
            let mut buf = [0u8; 4];
            xof.read(&mut buf);
            let val = u32::from_le_bytes(buf) & 0x7F_FFFF;
            if (val as i64) < Q {
                *coeff = val as i64;
                break;
            }
        }
    }
    poly
}

/// MLWE key pair used as a credential secret and public commitment source.
///
/// The secret vector is the witness for authorization proofs, and the public
/// vector is committed into the Merkle authorization set. Debug output redacts
/// the secret key, but callers must still avoid cloning or serializing it
/// outside controlled memory. A key pair is only meaningful under the
/// [`MlweParams`] used to generate it.
#[derive(ZeroizeOnDrop)]
pub struct MlweKeyPair {
    /// Secret key vector s ∈ R_q^k with small coefficients (‖s‖∞ ≤ η).
    pub(crate) secret_key: PolyVec,
    /// Public key vector b = A · s + e mod q ∈ R_q^k.
    pub(crate) public_key: PolyVec,
}

impl fmt::Debug for MlweKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlweKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl MlweKeyPair {
    /// Returns the public key vector `b = A * s + e`.
    ///
    /// # Security
    ///
    /// The returned value is public, but it is linkable through its commitment
    /// hash. Callers should not treat repeated public keys as unlinkable.
    pub fn public_key(&self) -> &PolyVec {
        &self.public_key
    }

    /// Computes the credential commitment for this public key.
    ///
    /// # Security
    ///
    /// The commitment is deterministic for a public key and is intended to be
    /// placed in a Merkle authorization set.
    pub fn commitment(&self) -> [u8; 32] {
        commitment_hash(&self.public_key)
    }

    /// Derives the scope-bound nullifier for this key pair.
    ///
    /// # Security
    ///
    /// The same key and scope produce the same nullifier. Callers must use a
    /// fresh, protocol-specific scope when linkability across sessions is not
    /// desired.
    pub fn nullifier(&self, scope: &[u8]) -> [u8; 32] {
        crate::zk_auth::derive_nullifier(&self.secret_key, scope)
    }
}

/// Generates an MLWE key pair for the supplied public parameters.
///
/// # Randomness
///
/// The `rng` parameter must be a cryptographically secure pseudorandom
/// number generator. Passing a weak or deterministic RNG breaks the
/// security of the output.
///
/// # Security
///
/// The returned secret key is the proof witness. It must not be logged,
/// serialized, or reused with unrelated protocol parameters.
pub fn keygen<R: RngCore + CryptoRng + ?Sized>(params: &MlweParams, rng: &mut R) -> MlweKeyPair {
    let secret_key = PolyVec::sample_cbd(rng);
    let error = PolyVec::sample_cbd(rng);

    let public_without_error = params.matrix_a.mul_vec(&secret_key);
    let public_key = public_without_error.add(&error);

    MlweKeyPair {
        secret_key,
        public_key,
    }
}

/// Computes the deterministic credential commitment for a public key.
///
/// # Security
///
/// The returned hash is domain-separated for credential commitments and is
/// intended to be inserted as a Merkle leaf. Callers must use the same public
/// key encoding for both insertion and verification.
pub fn commitment_hash(public_key: &PolyVec) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"COM_DOM");
    hasher.update(&public_key.to_bytes());
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

/// Samples a sparse Fiat-Shamir challenge polynomial from a transcript seed.
///
/// # Security
///
/// The seed must be derived from the full verification transcript under an
/// unambiguous domain separator. Reusing this sampler on incomplete transcripts
/// can break soundness assumptions.
pub fn sample_challenge(seed: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();

    let mut c = Poly::zero();

    let mut sign_bytes = [0u8; 8];
    xof.read(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    let mut positions = [0u16; N];
    for (i, position) in positions.iter_mut().enumerate() {
        *position = i as u16;
    }

    for i in 0..TAU {
        let bound = (N - i) as u16;
        let j = loop {
            let mut candidate_bytes = [0u8; 2];
            xof.read(&mut candidate_bytes);
            let val = u16::from_le_bytes(candidate_bytes) as u32;
            let bound = bound as u32;
            let zone = 65_536 - (65_536 % bound);
            if val < zone {
                break (val % bound) as usize;
            }
        };

        let swap_idx = N - 1 - i;
        positions.swap(swap_idx, j);

        let pos = positions[swap_idx] as usize;
        if (signs >> i) & 1 == 0 {
            c.coeffs[pos] = 1;
        } else {
            c.coeffs[pos] = crate::poly::Q - 1;
        }
    }

    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::{K, Q};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_keygen_public_key_structure() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(42);
        let params = MlweParams::generate(&mut rng);
        let keypair = keygen(&params, &mut rng);

        assert_eq!(keypair.public_key.polys.len(), K);
        assert_eq!(keypair.secret_key.polys.len(), K);

        for poly in &keypair.secret_key.polys {
            assert!(poly.infinity_norm() <= 2, "Secret key norm too large");
        }
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(43);
        let params = MlweParams::generate(&mut rng);
        let keypair = keygen(&params, &mut rng);

        let h1 = commitment_hash(&keypair.public_key);
        let h2 = commitment_hash(&keypair.public_key);
        assert_eq!(h1, h2, "Commitment hash must be deterministic");
    }

    #[test]
    fn test_commitment_hash_different_keys() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(44);
        let params = MlweParams::generate(&mut rng);
        let kp1 = keygen(&params, &mut rng);
        let kp2 = keygen(&params, &mut rng);

        let h1 = commitment_hash(&kp1.public_key);
        let h2 = commitment_hash(&kp2.public_key);
        assert_ne!(h1, h2, "Different keys must produce different hashes");
    }

    #[test]
    fn test_challenge_polynomial_weight() {
        let seed = b"test_challenge_seed_12345";
        let c = sample_challenge(seed);

        let nonzero_count = c.coeffs.iter().filter(|&&x| x != 0).count();
        assert_eq!(
            nonzero_count, TAU,
            "Challenge must have exactly τ = {} non-zero coefficients, got {}",
            TAU, nonzero_count
        );

        for &coeff in &c.coeffs {
            if coeff != 0 {
                assert!(
                    coeff == 1 || coeff == Q - 1,
                    "Non-zero challenge coefficient must be ±1, got {}",
                    coeff
                );
            }
        }
    }

    #[test]
    fn test_challenge_deterministic() {
        let seed = b"deterministic_test_seed";
        let c1 = sample_challenge(seed);
        let c2 = sample_challenge(seed);
        assert_eq!(c1, c2, "Same seed must produce same challenge");
    }

    #[test]
    fn test_challenge_different_seeds() {
        let c1 = sample_challenge(b"seed_A");
        let c2 = sample_challenge(b"seed_B");
        assert_ne!(c1, c2, "Different seeds must produce different challenges");
    }

    #[test]
    fn test_from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let params_a = MlweParams::from_seed(&seed);
        let params_b = MlweParams::from_seed(&seed);

        for (row_a, row_b) in params_a.matrix_a.rows.iter().zip(&params_b.matrix_a.rows) {
            for (poly_a, poly_b) in row_a.polys.iter().zip(&row_b.polys) {
                assert_eq!(poly_a.coeffs, poly_b.coeffs);
            }
        }
    }

    #[test]
    fn test_from_seed_differs_by_seed() {
        let params_a = MlweParams::from_seed(&[1u8; 32]);
        let params_b = MlweParams::from_seed(&[2u8; 32]);

        let differs = params_a
            .matrix_a
            .rows
            .iter()
            .zip(&params_b.matrix_a.rows)
            .any(|(row_a, row_b)| {
                row_a
                    .polys
                    .iter()
                    .zip(&row_b.polys)
                    .any(|(poly_a, poly_b)| poly_a.coeffs != poly_b.coeffs)
            });

        assert!(differs, "Different seeds must produce different parameters");
    }
}
