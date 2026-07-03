//! Polynomial arithmetic for the Obscura credential proof relation.
//!
//! This module implements arithmetic in `R_q = Z_q[X] / (X^256 + 1)` for
//! Module-LWE-style keys, responses, and verifier relations. It is intended to
//! resist malformed coefficient encodings by rejecting out-of-range serialized
//! data before arithmetic is performed. Arithmetic and norm-bound checks run
//! over fixed dimensions without secret-dependent early exits.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Ring dimension: polynomials have 256 coefficients.
pub const N: usize = 256;

/// Module rank: vectors/matrices are of dimension k = 2.
pub const K: usize = 2;

/// Prime modulus `q = 8_380_417 = 2^23 - 2^13 + 1`.
pub const Q: i64 = 8_380_417;

/// Half of q, used for centered representation conversion.
pub const Q_HALF: i64 = Q / 2;

/// Secret key coefficient bound (Centered Binomial Distribution parameter).
pub const ETA: i64 = 2;

/// Challenge polynomial weight: number of non-zero (±1) coefficients.
pub const TAU: usize = 39;

/// Masking vector uniform range: coefficients in `[-gamma1 + 1, gamma1]`.
pub const GAMMA1: i64 = 1 << 17;

/// Rejection bound: beta = tau * eta = 39 * 2 = 78.
///
/// This is the maximum infinity-norm contribution of c * s or c * e when
/// the challenge has tau non-zero +/-1 coefficients and the secret/error
/// coefficients are bounded by eta.
pub const BETA: i64 = (TAU as i64) * ETA;

#[inline]
fn ct_mask_from_bool(bit: u64) -> i64 {
    0i64.wrapping_sub((bit & 1) as i64)
}

#[inline]
fn ct_is_negative(value: i64) -> i64 {
    ct_mask_from_bool(((value as u64) >> 63) & 1)
}

#[inline]
fn ct_select_i64(a: i64, b: i64, mask: i64) -> i64 {
    (a & !mask) | (b & mask)
}

#[inline]
fn ct_ge_i64(a: i64, b: i64) -> i64 {
    let diff = (a as i128) - (b as i128);
    let lt = ((diff >> 127) & 1) as u64;
    ct_mask_from_bool(lt ^ 1)
}

#[inline]
fn ct_abs_i64(value: i64) -> i64 {
    let mask = ct_is_negative(value);
    (value ^ mask).wrapping_sub(mask)
}

#[inline]
fn add_mod_q(a: i64, b: i64) -> i64 {
    let sum = a + b;
    sum - (Q & ct_ge_i64(sum, Q))
}

#[inline]
fn sub_mod_q(a: i64, b: i64) -> i64 {
    let diff = a - b;
    diff + (Q & ct_is_negative(diff))
}

#[inline]
fn centered_coeff(c: i64) -> i64 {
    ct_select_i64(c, c - Q, ct_ge_i64(c, Q_HALF + 1))
}

#[inline]
fn ct_max_i64(a: i64, b: i64) -> i64 {
    ct_select_i64(a, b, ct_ge_i64(b, a + 1))
}

/// Polynomial element in `R_q = Z_q[X] / (X^256 + 1)`.
///
/// This type carries coefficient data used in public keys, secret keys,
/// masking vectors, challenges, and verifier relations. The type enforces the
/// fixed ring dimension; deserialization additionally enforces coefficients in
/// `[0, q)`. Operations traverse the full ring dimension and avoid
/// value-dependent branches in arithmetic and norm checks.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Poly {
    /// 256 coefficients representing a₀ + a₁X + a₂X² + ... + a₂₅₅X²⁵⁵.
    pub coeffs: [i64; N],
}

// Custom serde implementation for Poly because [i64; 256] is not
// natively supported by serde's derive macros (max array size = 32).
impl Serialize for Poly {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.coeffs.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Poly {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let vec = Vec::<i64>::deserialize(deserializer)?;
        if vec.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} coefficients, got {}",
                N,
                vec.len()
            )));
        }
        let mut coeffs = [0i64; N];
        coeffs.copy_from_slice(&vec);
        for &coeff in &coeffs {
            if !(0..Q).contains(&coeff) {
                return Err(serde::de::Error::custom(format!(
                    "coefficient out of range [0, {}): {}",
                    Q, coeff
                )));
            }
        }
        Ok(Poly { coeffs })
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// Returns the zero polynomial.
    ///
    /// # Security
    ///
    /// The value carries no entropy and must not be used as a secret or mask.
    #[must_use]
    pub fn zero() -> Self {
        Poly { coeffs: [0i64; N] }
    }

    /// Reduces all coefficients to `[0, q)`.
    ///
    /// # Timing
    ///
    /// This function uses Euclidean division and should not be used as the
    /// primary reduction step for secret arithmetic paths.
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = c.rem_euclid(Q);
        }
    }

    /// Computes the infinity norm in centered representation.
    ///
    /// # Timing
    ///
    /// This function scans every coefficient and uses branch-free comparisons
    /// for the centered absolute value and maximum update.
    #[must_use]
    pub fn infinity_norm(&self) -> i64 {
        let mut max = 0i64;
        for &c in &self.coeffs {
            let abs = ct_abs_i64(centered_coeff(c));
            max = ct_max_i64(max, abs);
        }
        max
    }

    /// Returns true when the centered infinity norm is strictly below `bound`.
    ///
    /// # Timing
    ///
    /// This function always scans all coefficients and accumulates the bound
    /// decision without early exit.
    #[must_use]
    pub fn infinity_norm_lt(&self, bound: i64) -> bool {
        let mut ok_mask = -1i64;
        for &c in &self.coeffs {
            let abs = ct_abs_i64(centered_coeff(c));
            ok_mask &= ct_ge_i64(bound - 1, abs);
        }
        ok_mask == -1
    }

    /// Adds two polynomials in `R_q`.
    ///
    /// # Timing
    ///
    /// This function has a fixed loop count and branch-free modular
    /// correction for canonical coefficients.
    #[must_use]
    pub fn add(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = add_mod_q(self.coeffs[i], other.coeffs[i]);
        }
        result
    }

    /// Subtracts `other` from `self` in `R_q`.
    ///
    /// # Timing
    ///
    /// This function has a fixed loop count and branch-free modular
    /// correction for canonical coefficients.
    #[must_use]
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = sub_mod_q(self.coeffs[i], other.coeffs[i]);
        }
        result
    }

    /// Multiplies two polynomials in `R_q = Z_q[X] / (X^256 + 1)`.
    ///
    /// Uses schoolbook multiplication with negacyclic reduction. Terms whose
    /// degree reaches `N` wrap back with a sign flip because `X^N = -1`.
    ///
    /// # Timing
    ///
    /// This function performs the same multiply-accumulate work regardless of
    /// coefficient values. The negacyclic wrap branch depends only on public
    /// loop indices.
    #[must_use]
    pub fn mul(&self, other: &Poly) -> Poly {
        let mut product_coeffs = [0i128; N];

        for i in 0..N {
            for j in 0..N {
                let product = (self.coeffs[i] as i128) * (other.coeffs[j] as i128);
                let idx = i + j;
                if idx < N {
                    product_coeffs[idx] += product;
                } else {
                    product_coeffs[idx - N] -= product;
                }
            }
        }

        let mut out = Poly::zero();
        for (out_coeff, value) in out.coeffs.iter_mut().zip(product_coeffs) {
            *out_coeff = (value.rem_euclid(Q as i128)) as i64;
        }
        out
    }

    /// Samples a polynomial from the centered binomial distribution with `eta = 2`.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_cbd<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Poly {
        let mut poly = Poly::zero();
        let mut bytes = [0u8; 128];
        rng.fill_bytes(&mut bytes);

        for i in 0..N {
            let bit_offset = i * 4;
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;

            let nibble = if bit_idx <= 4 {
                (bytes[byte_idx] >> bit_idx) & 0x0F
            } else {
                let lo = bytes[byte_idx] >> bit_idx;
                let hi = bytes[byte_idx + 1] << (8 - bit_idx);
                (lo | hi) & 0x0F
            };

            let a_bits = nibble & 0x03;
            let b_bits = (nibble >> 2) & 0x03;
            let a_count = (a_bits & 1) + ((a_bits >> 1) & 1);
            let b_count = (b_bits & 1) + ((b_bits >> 1) & 1);

            let coeff = (a_count as i64) - (b_count as i64);
            poly.coeffs[i] = coeff.rem_euclid(Q);
        }
        poly
    }

    /// Samples a polynomial with coefficients uniformly in `[0, q)`.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_uniform<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Poly {
        let mut poly = Poly::zero();
        for c in poly.coeffs.iter_mut() {
            loop {
                let mut candidate_bytes = [0u8; 4];
                rng.fill_bytes(&mut candidate_bytes);
                let candidate = u32::from_le_bytes(candidate_bytes) & 0x7F_FFFF;
                if (candidate as i64) < Q {
                    *c = candidate as i64;
                    break;
                }
            }
        }
        poly
    }

    /// Samples a masking polynomial with coefficients uniform in `[-gamma1 + 1, gamma1]`.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_masking<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Poly {
        let mut poly = Poly::zero();
        let range = 2 * GAMMA1;
        for c in poly.coeffs.iter_mut() {
            loop {
                let mut candidate_bytes = [0u8; 4];
                rng.fill_bytes(&mut candidate_bytes);
                let candidate = u32::from_le_bytes(candidate_bytes) & 0x0003_FFFF;
                if (candidate as i64) < range {
                    *c = ((candidate as i64) - GAMMA1 + 1).rem_euclid(Q);
                    break;
                }
            }
        }
        poly
    }

    /// Serializes the polynomial as little-endian 23-bit coefficients.
    ///
    /// # Security
    ///
    /// Callers must only serialize reduced coefficients when canonical
    /// encodings are required by a protocol transcript.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 3);
        for &c in &self.coeffs {
            let v = c as u32;
            bytes.push(v as u8);
            bytes.push((v >> 8) as u8);
            bytes.push((v >> 16) as u8);
        }
        bytes
    }

    /// Deserializes a polynomial from little-endian 23-bit coefficients.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural
    /// checks are performed before any arithmetic. Malformed input is
    /// rejected with `None` rather than panicking.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N * 3 {
            return None;
        }
        let mut poly = Poly::zero();
        for i in 0..N {
            let offset = i * 3;
            let v = (bytes[offset] as i64)
                | ((bytes[offset + 1] as i64) << 8)
                | ((bytes[offset + 2] as i64) << 16);
            if v >= Q {
                return None;
            }
            poly.coeffs[i] = v;
        }
        Some(poly)
    }
}

/// Vector of `k` polynomials in `R_q^k`.
///
/// This type carries MLWE secret vectors, public key vectors, and proof
/// responses. Deserialization enforces the module rank `K`; arithmetic assumes
/// operands already have that rank. Callers must avoid exposing vectors that
/// contain secret coefficients through debug output or unauthenticated
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Zeroize)]
pub struct PolyVec {
    /// Component polynomials.
    pub polys: Vec<Poly>,
}

impl<'de> Deserialize<'de> for PolyVec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PolyVecRepr {
            polys: Vec<Poly>,
        }

        let polys = PolyVecRepr::deserialize(deserializer)?.polys;
        if polys.len() != K {
            return Err(serde::de::Error::custom(format!(
                "expected {} polynomials, got {}",
                K,
                polys.len()
            )));
        }
        Ok(PolyVec { polys })
    }
}

impl PolyVec {
    /// Returns the zero vector of dimension `k`.
    ///
    /// # Security
    ///
    /// The value carries no entropy and must not be used as a secret vector or mask.
    #[must_use]
    pub fn zero() -> Self {
        PolyVec {
            polys: vec![Poly::zero(); K],
        }
    }

    /// Adds two polynomial vectors component-wise.
    ///
    /// # Timing
    ///
    /// This function dispatches to fixed-dimension polynomial addition.
    #[must_use]
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        debug_assert_eq!(self.polys.len(), K);
        debug_assert_eq!(other.polys.len(), K);
        PolyVec {
            polys: self
                .polys
                .iter()
                .zip(&other.polys)
                .map(|(a, b)| a.add(b))
                .collect(),
        }
    }

    /// Subtracts two polynomial vectors component-wise.
    ///
    /// # Timing
    ///
    /// This function dispatches to fixed-dimension polynomial subtraction.
    #[must_use]
    pub fn sub(&self, other: &PolyVec) -> PolyVec {
        debug_assert_eq!(self.polys.len(), K);
        debug_assert_eq!(other.polys.len(), K);
        PolyVec {
            polys: self
                .polys
                .iter()
                .zip(&other.polys)
                .map(|(a, b)| a.sub(b))
                .collect(),
        }
    }

    /// Multiplies each vector component by a scalar polynomial.
    ///
    /// # Timing
    ///
    /// This function dispatches to fixed-work polynomial multiplication for
    /// every vector component.
    #[must_use]
    pub fn scalar_mul(&self, scalar: &Poly) -> PolyVec {
        PolyVec {
            polys: self.polys.iter().map(|p| p.mul(scalar)).collect(),
        }
    }

    /// Computes the polynomial inner product `sum_i self[i] * other[i]`.
    ///
    /// # Timing
    ///
    /// This function performs the same number of component products for
    /// fixed-rank vectors.
    #[must_use]
    pub fn inner_product(&self, other: &PolyVec) -> Poly {
        debug_assert_eq!(self.polys.len(), K);
        debug_assert_eq!(other.polys.len(), K);
        let mut result = Poly::zero();
        for (a, b) in self.polys.iter().zip(&other.polys) {
            result = result.add(&a.mul(b));
        }
        result
    }

    /// Computes the maximum infinity norm across component polynomials.
    ///
    /// # Timing
    ///
    /// This function scans all component polynomials without early exit.
    #[must_use]
    pub fn infinity_norm(&self) -> i64 {
        let mut max = 0i64;
        for poly in &self.polys {
            max = ct_max_i64(max, poly.infinity_norm());
        }
        max
    }

    /// Returns true when every component polynomial is below `bound`.
    ///
    /// # Timing
    ///
    /// This function evaluates all component polynomials and accumulates the
    /// bound decision without short-circuiting.
    #[must_use]
    pub fn infinity_norm_lt(&self, bound: i64) -> bool {
        let mut ok = true;
        for poly in &self.polys {
            ok &= poly.infinity_norm_lt(bound);
        }
        ok
    }

    /// Samples a uniform random polynomial vector.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_uniform<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> PolyVec {
        PolyVec {
            polys: (0..K).map(|_| Poly::sample_uniform(rng)).collect(),
        }
    }

    /// Samples a centered-binomial polynomial vector.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_cbd<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> PolyVec {
        PolyVec {
            polys: (0..K).map(|_| Poly::sample_cbd(rng)).collect(),
        }
    }

    /// Samples a masking polynomial vector.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_masking<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> PolyVec {
        PolyVec {
            polys: (0..K).map(|_| Poly::sample_masking(rng)).collect(),
        }
    }

    /// Serializes all component polynomials in canonical order.
    ///
    /// # Security
    ///
    /// Callers must not serialize secret vectors into logs or unauthenticated
    /// storage. The encoding is deterministic and linkable.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for p in &self.polys {
            bytes.extend_from_slice(&p.to_bytes());
        }
        bytes
    }

    /// Deserializes a polynomial vector from its byte encoding.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural
    /// checks are performed before any arithmetic. Malformed input is
    /// rejected with `None` rather than panicking.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let poly_size = N * 3;
        if bytes.len() != K * poly_size {
            return None;
        }
        let mut polys = Vec::with_capacity(K);
        for i in 0..K {
            let start = i * poly_size;
            let end = start + poly_size;
            polys.push(Poly::from_bytes(&bytes[start..end])?);
        }
        Some(PolyVec { polys })
    }
}

/// Matrix of polynomials in `R_q^{k x k}`.
///
/// This type carries the public Module-LWE parameter matrix used to bind public
/// keys and proof responses. Matrix values are public protocol parameters and
/// do not enforce a trusted setup by themselves. Callers must ensure all
/// parties use the same matrix when producing and verifying proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolyMat {
    /// Rows of the matrix. `rows[i]` is the i-th row vector.
    pub rows: Vec<PolyVec>,
}

impl<'de> Deserialize<'de> for PolyMat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PolyMatRepr {
            rows: Vec<PolyVec>,
        }

        let rows = PolyMatRepr::deserialize(deserializer)?.rows;
        if rows.len() != K {
            return Err(serde::de::Error::custom(format!(
                "expected {} matrix rows, got {}",
                K,
                rows.len()
            )));
        }
        Ok(PolyMat { rows })
    }
}

impl PolyMat {
    /// Samples a uniform random `k x k` polynomial matrix.
    ///
    /// # Randomness
    ///
    /// The `rng` parameter must be a cryptographically secure pseudorandom
    /// number generator. Passing a weak or deterministic RNG breaks the
    /// security of the output.
    pub fn sample_uniform<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> PolyMat {
        PolyMat {
            rows: (0..K).map(|_| PolyVec::sample_uniform(rng)).collect(),
        }
    }

    /// Computes the matrix-vector product `A * v`.
    ///
    /// # Timing
    ///
    /// This function has fixed work for valid `k x k` matrices and vectors.
    #[must_use]
    pub fn mul_vec(&self, v: &PolyVec) -> PolyVec {
        debug_assert_eq!(self.rows.len(), K);
        debug_assert_eq!(v.polys.len(), K);
        PolyVec {
            polys: self.rows.iter().map(|row| row.inner_product(v)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_poly_add_sub_identity() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(42);
        let a = Poly::sample_uniform(&mut rng);
        let b = Poly::sample_uniform(&mut rng);
        let sum = a.add(&b);
        let recovered = sum.sub(&b);
        assert_eq!(a, recovered);
    }

    #[test]
    fn test_poly_mul_commutativity() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(43);
        let a = Poly::sample_uniform(&mut rng);
        let b = Poly::sample_uniform(&mut rng);
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_poly_mul_by_zero() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(44);
        let a = Poly::sample_uniform(&mut rng);
        let zero = Poly::zero();
        assert_eq!(a.mul(&zero), zero);
    }

    #[test]
    fn test_poly_mul_by_one() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(45);
        let a = Poly::sample_uniform(&mut rng);
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        assert_eq!(a.mul(&one), a);
    }

    #[test]
    fn test_cbd_range() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(46);
        let p = Poly::sample_cbd(&mut rng);
        for &c in &p.coeffs {
            // CBD(2) produces values in [-2, 2], which mod q are
            // {0, 1, 2, q-2, q-1}.
            let centered = if c > Q_HALF { c - Q } else { c };
            assert!(
                centered.abs() <= ETA,
                "CBD coefficient {} out of range [-{}, {}]",
                centered,
                ETA,
                ETA
            );
        }
    }

    #[test]
    fn test_poly_serialization_roundtrip() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(47);
        let p = Poly::sample_uniform(&mut rng);
        let bytes = p.to_bytes();
        let recovered = Poly::from_bytes(&bytes).unwrap();
        assert_eq!(p, recovered);
    }

    #[test]
    fn test_polyvec_serialization_roundtrip() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(48);
        let v = PolyVec::sample_uniform(&mut rng);
        let bytes = v.to_bytes();
        let recovered = PolyVec::from_bytes(&bytes).unwrap();
        assert_eq!(v, recovered);
    }

    #[test]
    fn test_poly_deserialize_rejects_out_of_range_coefficients() {
        let mut coeffs = vec![0i64; N];
        coeffs[17] = Q; // simulate a coefficient outside the canonical range
        let encoded = serde_json::to_vec(&coeffs).unwrap();

        assert!(serde_json::from_slice::<Poly>(&encoded).is_err());
    }

    #[test]
    fn test_polyvec_deserialize_rejects_wrong_dimension() {
        // simulate a payload with the wrong module rank
        let encoded = serde_json::json!({
            "polys": [Poly::zero()]
        })
        .to_string();

        assert!(serde_json::from_str::<PolyVec>(&encoded).is_err());
    }

    #[test]
    fn test_matrix_vec_mul_dimensions() {
        // Seeded for test determinism. Production code must use OsRng.
        let mut rng = StdRng::seed_from_u64(49);
        let a = PolyMat::sample_uniform(&mut rng);
        let v = PolyVec::sample_uniform(&mut rng);
        let result = a.mul_vec(&v);
        assert_eq!(result.polys.len(), K);
    }

    #[test]
    fn test_infinity_norm() {
        let mut p = Poly::zero();
        p.coeffs[0] = 100;
        p.coeffs[1] = Q - 50; // represents -50 in centered form
        assert_eq!(p.infinity_norm(), 100);

        let mut p2 = Poly::zero();
        p2.coeffs[0] = Q - 200; // represents -200
        assert_eq!(p2.infinity_norm(), 200);
    }

    #[test]
    fn test_negacyclic_reduction() {
        let mut a = Poly::zero();
        a.coeffs[128] = 1;
        let result = a.mul(&a);
        let mut expected = Poly::zero();
        expected.coeffs[0] = Q - 1;
        assert_eq!(result, expected);
    }
}
