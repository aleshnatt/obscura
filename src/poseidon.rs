//! # Obscura Protocol — Poseidon Hash
//!
//! SNARK-friendly Poseidon hash function for the BN254 scalar field.
//!
//! Poseidon is an algebraic hash function designed for efficient
//! representation in arithmetic circuits (R1CS / PLONK). It operates
//! natively over prime field elements, requiring only ~300 R1CS
//! constraints per invocation — compared to ~27,000 for SHA-256.
//!
//! ## Parameters
//!
//! The configuration used here follows the Poseidon paper's
//! recommendations for 128-bit security on BN254:
//!
//! - **Rate**: 2 (absorbs 2 field elements per permutation)
//! - **Capacity**: 1
//! - **Full rounds**: 8 (4 at start + 4 at end)
//! - **Partial rounds**: 57 (field-dependent, for 254-bit primes)
//! - **S-box exponent**: α = 5

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};

/// Generate the standard Poseidon configuration for BN254 Fr.
///
/// Round constants (ARK) and MDS matrix are derived via the Grain LFSR
/// method specified in the Poseidon paper, ensuring cryptographic security.
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds: u64 = 8;
    let partial_rounds: u64 = 57;
    let alpha: u64 = 5;
    let rate: usize = 2;
    let capacity: usize = 1;

    // Generate round constants and MDS matrix using the Grain LFSR method.
    // Parameters: field_size_bits, rate, full_rounds, partial_rounds, skip_matrices
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        254, // BN254 scalar field is 254 bits
        rate,
        full_rounds,
        partial_rounds,
        0, // skip_matrices = 0 (use first valid MDS)
    );

    PoseidonConfig {
        full_rounds: full_rounds as usize,
        partial_rounds: partial_rounds as usize,
        alpha,
        ark,
        mds,
        rate,
        capacity,
    }
}

/// Compute Poseidon hash of one or more field elements.
///
/// Uses the sponge construction: absorb all inputs, then squeeze
/// one field element as the hash output.
///
/// `H(x₁, x₂, ..., xₙ) → Fr`
pub fn poseidon_hash(config: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config);
    let input_vec: Vec<Fr> = inputs.to_vec();
    sponge.absorb(&input_vec);
    let result = sponge.squeeze_native_field_elements(1);
    result[0]
}

/// Compute 2-to-1 Poseidon hash (optimized for Merkle tree internal nodes).
///
/// `H(left, right) → Fr`
pub fn poseidon_hash_two(config: &PoseidonConfig<Fr>, left: &Fr, right: &Fr) -> Fr {
    poseidon_hash(config, &[*left, *right])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_poseidon_deterministic() {
        let config = poseidon_config();
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let h1 = poseidon_hash(&config, &[a, b]);
        let h2 = poseidon_hash(&config, &[a, b]);
        assert_eq!(h1, h2, "Poseidon hash must be deterministic");
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let config = poseidon_config();
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = Fr::rand(&mut rng);

        let h1 = poseidon_hash(&config, &[a, b]);
        let h2 = poseidon_hash(&config, &[a, c]);
        assert_ne!(h1, h2, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_poseidon_hash_two() {
        let config = poseidon_config();
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let h1 = poseidon_hash_two(&config, &a, &b);
        let h2 = poseidon_hash(&config, &[a, b]);
        assert_eq!(h1, h2, "poseidon_hash_two must equal poseidon_hash with 2 inputs");
    }
}
