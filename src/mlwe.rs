//! # Obscura Protocol — Module-LWE Primitives
//!
//! Implements the Module Learning with Errors (Module-LWE) key generation
//! and challenge sampling for the post-quantum ZK authorization protocol.
//!
//! ## Parameters
//!
//! - Ring: R_q = Z_q\[X\]/(X^256 + 1), q = 8,380,417
//! - Module rank k = 2
//! - Secret/error bound η = 2 (Centered Binomial Distribution)
//!
//! ## Key Generation
//!
//! 1. Generate public matrix A ∈ R_q^{k×k} uniformly at random.
//! 2. Sample secret s ← CBD(η)^k and error e ← CBD(η)^k.
//! 3. Compute public key b = A · s + e mod q.
//!
//! ## Challenge Sampling
//!
//! The challenge polynomial c ∈ R_q has exactly τ = 39 non-zero coefficients,
//! each ±1, and is derived deterministically from the transcript hash
//! via SHAKE-256.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::ZeroizeOnDrop;

use crate::poly::{N, Poly, PolyMat, PolyVec, TAU};

// ─── Public Parameters ───────────────────────────────────────────────────────

/// Module-LWE public parameters.
///
/// Contains the public matrix A which is generated uniformly at random.
/// In a real deployment, A would be expanded deterministically from a
/// small seed using SHAKE-256 to reduce parameter size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlweParams {
    /// The public k × k polynomial matrix A ∈ R_q^{k×k}.
    pub matrix_a: PolyMat,
}

impl MlweParams {
    /// Generate fresh MLWE parameters (random matrix A).
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        MlweParams {
            matrix_a: PolyMat::sample_uniform(rng),
        }
    }
}

// ─── Key Pair ────────────────────────────────────────────────────────────────

/// An MLWE key pair for the ZK authorization protocol.
///
/// - `secret_key`: s ∈ R_q^k sampled from CBD(η).
/// - `public_key`: b = A · s + e mod q ∈ R_q^k.
///
/// The public key commitment hash is SHAKE-256("COM_DOM" ∥ serialize(b)).
#[derive(ZeroizeOnDrop)]
pub struct MlweKeyPair {
    /// Secret key vector s ∈ R_q^k with small coefficients (‖s‖∞ ≤ η).
    pub secret_key: PolyVec,
    /// Public key vector b = A · s + e mod q ∈ R_q^k.
    pub public_key: PolyVec,
}

/// Generate an MLWE key pair.
///
/// 1. Sample s ← CBD(η)^k (secret key with small coefficients).
/// 2. Sample e ← CBD(η)^k (error vector with small coefficients).
/// 3. Compute b = A · s + e mod q (public key).
pub fn keygen<R: RngCore + CryptoRng + ?Sized>(params: &MlweParams, rng: &mut R) -> MlweKeyPair {
    let s = PolyVec::sample_cbd(rng);
    let e = PolyVec::sample_cbd(rng);

    // b = A · s + e mod q
    let as_product = params.matrix_a.mul_vec(&s);
    let b = as_product.add(&e);

    MlweKeyPair {
        secret_key: s,
        public_key: b,
    }
}

/// Compute the commitment hash of a public key.
///
/// commitment = SHAKE-256("COM_DOM" ∥ serialize(b)), truncated to 32 bytes.
///
/// This value is inserted as a leaf into the Merkle tree.
pub fn commitment_hash(public_key: &PolyVec) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"COM_DOM");
    hasher.update(&public_key.to_bytes());
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

// ─── Challenge Sampling ──────────────────────────────────────────────────────

/// Sample a challenge polynomial c ∈ R_q with exactly τ non-zero coefficients.
///
/// The challenge is derived deterministically from a hash seed using SHAKE-256:
/// 1. Initialize SHAKE-256 XOF with the seed bytes.
/// 2. Use rejection sampling from the XOF output to select τ distinct
///    coefficient positions (Fisher-Yates-like selection).
/// 3. For each position, read one more byte to determine the sign (±1).
///
/// The result is a polynomial with exactly τ coefficients set to +1 or -1,
/// and all remaining coefficients zero. This construction ensures that
/// ‖c‖₁ = τ and ‖c‖∞ = 1.
pub fn sample_challenge(seed: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();

    let mut c = Poly::zero();

    // Read 8 bytes for the sign bits (we need τ = 39 sign bits).
    let mut sign_bytes = [0u8; 8];
    xof.read(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    // Fisher-Yates-style position selection.
    // Start with positions [0..N-1] available; select τ random distinct positions.
    let mut positions = [0u16; N];
    for (i, position) in positions.iter_mut().enumerate() {
        *position = i as u16;
    }

    for i in 0..TAU {
        // Sample a random index in [0, N - i) by rejection.
        let bound = (N - i) as u16;
        let j = loop {
            let mut buf = [0u8; 2];
            xof.read(&mut buf);
            let val = u16::from_le_bytes(buf) as u32;
            let bound = bound as u32;
            let zone = 65_536 - (65_536 % bound);
            if val < zone {
                break (val % bound) as usize;
            }
        };

        // Swap positions[N-1-i] and positions[j].
        let swap_idx = N - 1 - i;
        positions.swap(swap_idx, j);

        // Assign ±1 based on sign bit.
        let pos = positions[swap_idx] as usize;
        if (signs >> i) & 1 == 0 {
            c.coeffs[pos] = 1;
        } else {
            c.coeffs[pos] = crate::poly::Q - 1; // -1 mod q
        }
    }

    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::{K, Q};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_keygen_public_key_structure() {
        let mut rng = StdRng::seed_from_u64(42);
        let params = MlweParams::generate(&mut rng);
        let keypair = keygen(&params, &mut rng);

        // Public key should have k polynomials.
        assert_eq!(keypair.public_key.polys.len(), K);
        // Secret key should have k polynomials.
        assert_eq!(keypair.secret_key.polys.len(), K);

        // Secret key coefficients should be small (CBD bound).
        for poly in &keypair.secret_key.polys {
            assert!(poly.infinity_norm() <= 2, "Secret key norm too large");
        }
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        let mut rng = StdRng::seed_from_u64(43);
        let params = MlweParams::generate(&mut rng);
        let keypair = keygen(&params, &mut rng);

        let h1 = commitment_hash(&keypair.public_key);
        let h2 = commitment_hash(&keypair.public_key);
        assert_eq!(h1, h2, "Commitment hash must be deterministic");
    }

    #[test]
    fn test_commitment_hash_different_keys() {
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

        // Count non-zero coefficients.
        let nonzero_count = c.coeffs.iter().filter(|&&x| x != 0).count();
        assert_eq!(
            nonzero_count, TAU,
            "Challenge must have exactly τ = {} non-zero coefficients, got {}",
            TAU, nonzero_count
        );

        // All non-zero coefficients must be ±1 (i.e., 1 or q-1).
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
}
