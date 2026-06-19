//! # Obscura Protocol — Polynomial Arithmetic
//!
//! Implements polynomial arithmetic in the ring:
//!
//!   R_q = ℤ_q[X] / (X^256 + 1)
//!
//! with parameters:
//! - Ring dimension n = 256
//! - Modulus q = 8,380,417 (NTT-friendly prime, q ≡ 1 mod 512)
//!
//! ## Types
//!
//! - [`Poly`]: A single polynomial with 256 coefficients in [0, q).
//! - [`PolyVec`]: A vector of k polynomials (module rank k = 2).
//! - [`PolyMat`]: A k × k matrix of polynomials.
//!
//! ## Operations
//!
//! Polynomial multiplication uses schoolbook multiplication reduced
//! modulo X^256 + 1 (negacyclic convolution). All arithmetic is
//! performed with signed intermediate values and reduced to [0, q).

use rand::RngCore;
use serde::{Deserialize, Serialize};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Ring dimension: polynomials have 256 coefficients.
pub const N: usize = 256;

/// Module rank: vectors/matrices are of dimension k = 2.
pub const K: usize = 2;

/// Prime modulus. q = 8,380,417 = 2^23 - 2^13 + 1.
/// This is NTT-friendly: q ≡ 1 (mod 512), enabling efficient transforms.
pub const Q: i64 = 8_380_417;

/// Half of q, used for centered representation conversion.
pub const Q_HALF: i64 = Q / 2;

/// Secret key coefficient bound (Centered Binomial Distribution parameter).
pub const ETA: u32 = 2;

/// Challenge polynomial weight: number of non-zero (±1) coefficients.
pub const TAU: usize = 39;

/// Masking vector uniform range: coefficients in [-γ₁+1, γ₁].
pub const GAMMA1: i64 = 1 << 17; // 131,072

/// Rejection bound: β = τ · η · 2 = 39 · 2 · 2 = 156.
pub const BETA: i64 = (TAU as i64) * (ETA as i64) * 2;

// ─── Polynomial ──────────────────────────────────────────────────────────────

/// A polynomial in R_q = ℤ_q[X]/(X^256 + 1).
///
/// Coefficients are stored in standard (non-NTT) form as values in [0, q).
#[derive(Debug, Clone, PartialEq, Eq)]
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
        Ok(Poly { coeffs })
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Poly { coeffs: [0i64; N] }
    }

    /// Reduce all coefficients to [0, q).
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = c.rem_euclid(Q);
        }
    }

    /// Compute the infinity norm of the polynomial in centered representation.
    ///
    /// Maps each coefficient c ∈ [0, q) to [-q/2, q/2] and returns max |c|.
    pub fn infinity_norm(&self) -> i64 {
        let mut max = 0i64;
        for &c in &self.coeffs {
            let centered = if c > Q_HALF { c - Q } else { c };
            let abs = centered.abs();
            if abs > max {
                max = abs;
            }
        }
        max
    }

    /// Add two polynomials in R_q.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]).rem_euclid(Q);
        }
        result
    }

    /// Subtract: self - other mod q.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = (self.coeffs[i] - other.coeffs[i]).rem_euclid(Q);
        }
        result
    }

    /// Multiply two polynomials in R_q = ℤ_q[X]/(X^256 + 1).
    ///
    /// Uses schoolbook multiplication with negacyclic reduction:
    /// X^256 ≡ -1, so if the product coefficient index ≥ N,
    /// it wraps around with a sign flip.
    pub fn mul(&self, other: &Poly) -> Poly {
        let mut result = [0i128; N];

        for i in 0..N {
            if self.coeffs[i] == 0 {
                continue;
            }
            for j in 0..N {
                if other.coeffs[j] == 0 {
                    continue;
                }
                let product = (self.coeffs[i] as i128) * (other.coeffs[j] as i128);
                let idx = i + j;
                if idx < N {
                    result[idx] += product;
                } else {
                    // X^N ≡ -1 in the negacyclic ring
                    result[idx - N] -= product;
                }
            }
        }

        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = (result[i].rem_euclid(Q as i128)) as i64;
        }
        out
    }

    /// Sample a polynomial with coefficients from the Centered Binomial
    /// Distribution CBD(η) where η = 2.
    ///
    /// For each coefficient: sample 2η uniform bits, split into two halves,
    /// compute (popcount(first_half) - popcount(second_half)).
    /// Result is in [-η, η] = [-2, 2].
    pub fn sample_cbd(rng: &mut dyn RngCore) -> Poly {
        let mut poly = Poly::zero();
        // For η=2, we need 2*η = 4 bits per coefficient, so 4*256 = 1024 bits = 128 bytes.
        let mut bytes = [0u8; 128];
        rng.fill_bytes(&mut bytes);

        for i in 0..N {
            // Extract 4 bits for coefficient i.
            let bit_offset = i * 4;
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;

            let nibble = if bit_idx <= 4 {
                (bytes[byte_idx] >> bit_idx) & 0x0F
            } else {
                // Spans two bytes.
                let lo = bytes[byte_idx] >> bit_idx;
                let hi = bytes[byte_idx + 1] << (8 - bit_idx);
                (lo | hi) & 0x0F
            };

            // First 2 bits → a, last 2 bits → b. Coefficient = popcount(a) - popcount(b).
            let a_bits = nibble & 0x03;
            let b_bits = (nibble >> 2) & 0x03;
            let a_count = (a_bits & 1) + ((a_bits >> 1) & 1);
            let b_count = (b_bits & 1) + ((b_bits >> 1) & 1);

            let coeff = (a_count as i64) - (b_count as i64);
            poly.coeffs[i] = coeff.rem_euclid(Q);
        }
        poly
    }

    /// Sample a polynomial with coefficients uniformly in [0, q).
    pub fn sample_uniform(rng: &mut dyn RngCore) -> Poly {
        let mut poly = Poly::zero();
        for c in poly.coeffs.iter_mut() {
            loop {
                let mut buf = [0u8; 4];
                rng.fill_bytes(&mut buf);
                let val = u32::from_le_bytes(buf) & 0x7F_FFFF; // 23-bit mask (q < 2^23)
                if (val as i64) < Q {
                    *c = val as i64;
                    break;
                }
            }
        }
        poly
    }

    /// Sample a masking polynomial with coefficients uniform in [-γ₁+1, γ₁].
    ///
    /// The range has width 2·γ₁ = 262,144 values.
    pub fn sample_masking(rng: &mut dyn RngCore) -> Poly {
        let mut poly = Poly::zero();
        let range = 2 * GAMMA1; // 262,144
        for c in poly.coeffs.iter_mut() {
            loop {
                let mut buf = [0u8; 4];
                rng.fill_bytes(&mut buf);
                let val = u32::from_le_bytes(buf) & 0x0003_FFFF; // 18-bit mask
                if (val as i64) < range {
                    // Map [0, range) → [-γ₁+1, γ₁]
                    *c = ((val as i64) - GAMMA1 + 1).rem_euclid(Q);
                    break;
                }
            }
        }
        poly
    }

    /// Serialize polynomial to bytes (little-endian, 3 bytes per coefficient).
    ///
    /// Each coefficient c ∈ [0, q) where q < 2^23, so 3 bytes suffice.
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

    /// Deserialize polynomial from bytes (little-endian, 3 bytes per coefficient).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < N * 3 {
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

// ─── Polynomial Vector ───────────────────────────────────────────────────────

/// A vector of k polynomials in R_q^k.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolyVec {
    pub polys: Vec<Poly>,
}

impl PolyVec {
    /// Zero vector of dimension k.
    pub fn zero() -> Self {
        PolyVec {
            polys: vec![Poly::zero(); K],
        }
    }

    /// Component-wise addition of two polynomial vectors.
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.polys.len(), other.polys.len());
        PolyVec {
            polys: self
                .polys
                .iter()
                .zip(&other.polys)
                .map(|(a, b)| a.add(b))
                .collect(),
        }
    }

    /// Component-wise subtraction.
    pub fn sub(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.polys.len(), other.polys.len());
        PolyVec {
            polys: self
                .polys
                .iter()
                .zip(&other.polys)
                .map(|(a, b)| a.sub(b))
                .collect(),
        }
    }

    /// Scalar multiplication: multiply each component by a scalar polynomial.
    pub fn scalar_mul(&self, scalar: &Poly) -> PolyVec {
        PolyVec {
            polys: self.polys.iter().map(|p| p.mul(scalar)).collect(),
        }
    }

    /// Inner product of two vectors: Σᵢ self[i] · other[i].
    pub fn inner_product(&self, other: &PolyVec) -> Poly {
        assert_eq!(self.polys.len(), other.polys.len());
        let mut result = Poly::zero();
        for (a, b) in self.polys.iter().zip(&other.polys) {
            result = result.add(&a.mul(b));
        }
        result
    }

    /// Maximum infinity norm across all component polynomials.
    pub fn infinity_norm(&self) -> i64 {
        self.polys.iter().map(|p| p.infinity_norm()).max().unwrap_or(0)
    }

    /// Sample a uniform random polynomial vector.
    pub fn sample_uniform(rng: &mut dyn RngCore) -> PolyVec {
        PolyVec {
            polys: (0..K).map(|_| Poly::sample_uniform(rng)).collect(),
        }
    }

    /// Sample a CBD polynomial vector.
    pub fn sample_cbd(rng: &mut dyn RngCore) -> PolyVec {
        PolyVec {
            polys: (0..K).map(|_| Poly::sample_cbd(rng)).collect(),
        }
    }

    /// Sample a masking polynomial vector.
    pub fn sample_masking(rng: &mut dyn RngCore) -> PolyVec {
        PolyVec {
            polys: (0..K).map(|_| Poly::sample_masking(rng)).collect(),
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for p in &self.polys {
            bytes.extend_from_slice(&p.to_bytes());
        }
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let poly_size = N * 3;
        if bytes.len() < K * poly_size {
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

// ─── Polynomial Matrix ───────────────────────────────────────────────────────

/// A k × k matrix of polynomials in R_q^{k×k}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyMat {
    /// Rows of the matrix. rows[i] is the i-th row vector.
    pub rows: Vec<PolyVec>,
}

impl PolyMat {
    /// Generate a uniform random k × k polynomial matrix.
    pub fn sample_uniform(rng: &mut dyn RngCore) -> PolyMat {
        PolyMat {
            rows: (0..K).map(|_| PolyVec::sample_uniform(rng)).collect(),
        }
    }

    /// Matrix-vector product: A · v, where A is k×k and v is k×1.
    ///
    /// Returns a k×1 polynomial vector where result[i] = Σⱼ A[i][j] · v[j].
    pub fn mul_vec(&self, v: &PolyVec) -> PolyVec {
        assert_eq!(self.rows.len(), K);
        PolyVec {
            polys: self
                .rows
                .iter()
                .map(|row| row.inner_product(v))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_poly_add_sub_identity() {
        let mut rng = StdRng::seed_from_u64(42);
        let a = Poly::sample_uniform(&mut rng);
        let b = Poly::sample_uniform(&mut rng);
        let sum = a.add(&b);
        let recovered = sum.sub(&b);
        assert_eq!(a, recovered);
    }

    #[test]
    fn test_poly_mul_commutativity() {
        let mut rng = StdRng::seed_from_u64(43);
        let a = Poly::sample_uniform(&mut rng);
        let b = Poly::sample_uniform(&mut rng);
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_poly_mul_by_zero() {
        let mut rng = StdRng::seed_from_u64(44);
        let a = Poly::sample_uniform(&mut rng);
        let zero = Poly::zero();
        assert_eq!(a.mul(&zero), zero);
    }

    #[test]
    fn test_poly_mul_by_one() {
        let mut rng = StdRng::seed_from_u64(45);
        let a = Poly::sample_uniform(&mut rng);
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        assert_eq!(a.mul(&one), a);
    }

    #[test]
    fn test_cbd_range() {
        let mut rng = StdRng::seed_from_u64(46);
        let p = Poly::sample_cbd(&mut rng);
        for &c in &p.coeffs {
            // CBD(2) produces values in [-2, 2], which mod q are
            // {0, 1, 2, q-2, q-1}.
            let centered = if c > Q_HALF { c - Q } else { c };
            assert!(
                centered.abs() <= ETA as i64,
                "CBD coefficient {} out of range [-{}, {}]",
                centered,
                ETA,
                ETA
            );
        }
    }

    #[test]
    fn test_poly_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(47);
        let p = Poly::sample_uniform(&mut rng);
        let bytes = p.to_bytes();
        let recovered = Poly::from_bytes(&bytes).unwrap();
        assert_eq!(p, recovered);
    }

    #[test]
    fn test_polyvec_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(48);
        let v = PolyVec::sample_uniform(&mut rng);
        let bytes = v.to_bytes();
        let recovered = PolyVec::from_bytes(&bytes).unwrap();
        assert_eq!(v, recovered);
    }

    #[test]
    fn test_matrix_vec_mul_dimensions() {
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
        // X^N ≡ -1 in ℤ_q[X]/(X^256+1)
        // So X^128 · X^128 = X^256 = -1 (mod X^256+1)
        let mut a = Poly::zero();
        a.coeffs[128] = 1; // a = X^128
        let result = a.mul(&a); // X^128 · X^128 = X^256 ≡ -1
        let mut expected = Poly::zero();
        expected.coeffs[0] = Q - 1; // -1 mod q
        assert_eq!(result, expected);
    }
}
