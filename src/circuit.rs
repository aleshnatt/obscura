//! # Obscura Protocol — ZK Circuit (R1CS)
//!
//! Implements the authentication relation R_auth as an R1CS circuit
//! for Groth16 proving over BN254.
//!
//! ## Circuit Relation
//!
//! The circuit proves knowledge of a private witness `w = (sk, nonce, challenge, path)`
//! such that:
//!
//! 1. **Commitment**: `leaf = Poseidon(0, Poseidon(sk, nonce))` — the prover knows
//!    the preimage of a committed leaf in the Merkle tree.
//!
//! 2. **Merkle membership**: The leaf is included in the tree with the public root ρ,
//!    verified by hashing up the sibling path.
//!
//! 3. **Nullifier**: `nullifier = Poseidon(sk, challenge)` — binds the proof to the
//!    server's challenge without revealing sk.
//!
//! ## Public Inputs (visible to verifier)
//!
//! 1. `merkle_root` (Fr)
//! 2. `nullifier` (Fr)
//!
//! ## Private Witness (known only to prover)
//!
//! - `secret_key` (Fr)
//! - `nonce` (Fr)
//! - `challenge` (Fr)
//! - `merkle_siblings` (Vec<Fr>, depth-many)
//! - `path_indices` (Vec<bool>, depth-many)

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ff::Zero;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// The Obscura authentication circuit.
///
/// Implements `ConstraintSynthesizer<Fr>` for use with `ark-groth16`.
/// A single instance of this circuit is used for trusted setup (with `None`
/// witness values), and then concrete instances (with `Some` values) are
/// used for proof generation.
pub struct ObscuraCircuit {
    /// Poseidon hash configuration (same for native and in-circuit operations).
    pub poseidon_config: PoseidonConfig<Fr>,
    /// Merkle tree depth (determines the number of sibling/path_index variables).
    pub tree_depth: usize,

    // ── Public Inputs ──
    /// The Merkle root of the anonymity set.
    pub merkle_root: Option<Fr>,
    /// The nullifier: Poseidon(sk, challenge).
    pub nullifier: Option<Fr>,

    // ── Private Witness ──
    /// The user's secret key.
    pub secret_key: Option<Fr>,
    /// The blinding factor used in the commitment.
    pub nonce: Option<Fr>,
    /// The server-issued authentication challenge.
    pub challenge: Option<Fr>,
    /// Sibling hashes along the Merkle path.
    pub merkle_siblings: Vec<Option<Fr>>,
    /// Path direction bits (false = left child, true = right child).
    pub path_indices: Vec<Option<bool>>,
}

impl ObscuraCircuit {
    /// Create a dummy circuit for trusted setup (all witness values are None).
    pub fn dummy(poseidon_config: PoseidonConfig<Fr>, tree_depth: usize) -> Self {
        ObscuraCircuit {
            poseidon_config,
            tree_depth,
            merkle_root: None,
            nullifier: None,
            secret_key: None,
            nonce: None,
            challenge: None,
            merkle_siblings: vec![None; tree_depth],
            path_indices: vec![None; tree_depth],
        }
    }
}

/// Helper: compute Poseidon hash of two field element variables inside the circuit.
fn poseidon_hash_var(
    cs: ConstraintSystemRef<Fr>,
    config: &PoseidonConfig<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, config);
    let input = vec![a.clone(), b.clone()];
    CryptographicSpongeVar::absorb(&mut sponge, &input)?;
    let output = CryptographicSpongeVar::squeeze_field_elements(&mut sponge, 1)?;
    Ok(output[0].clone())
}

impl ConstraintSynthesizer<Fr> for ObscuraCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Extract fields (partial move from self) ──
        let config = self.poseidon_config;
        let tree_depth = self.tree_depth;
        let merkle_root_val = self.merkle_root;
        let nullifier_val = self.nullifier;
        let secret_key_val = self.secret_key;
        let nonce_val = self.nonce;
        let challenge_val = self.challenge;
        let merkle_siblings_val = self.merkle_siblings;
        let path_indices_val = self.path_indices;

        // ══════════════════════════════════════════════════════════════════
        // PUBLIC INPUTS — visible to the verifier
        // ══════════════════════════════════════════════════════════════════

        // Public input 1: Merkle root of the anonymity set.
        let root_var = FpVar::new_input(cs.clone(), || {
            merkle_root_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input 2: Nullifier (prevents replay without deanonymizing).
        let nullifier_var = FpVar::new_input(cs.clone(), || {
            nullifier_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ══════════════════════════════════════════════════════════════════
        // PRIVATE WITNESS — known only to the prover
        // ══════════════════════════════════════════════════════════════════

        let sk_var = FpVar::new_witness(cs.clone(), || {
            secret_key_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nonce_var = FpVar::new_witness(cs.clone(), || {
            nonce_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let challenge_var = FpVar::new_witness(cs.clone(), || {
            challenge_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ══════════════════════════════════════════════════════════════════
        // CONSTRAINT 1: Commitment
        // leaf_preimage = Poseidon(sk, nonce)
        // leaf = Poseidon(0, leaf_preimage)   [domain-separated leaf hash]
        // ══════════════════════════════════════════════════════════════════

        let commitment_var = poseidon_hash_var(cs.clone(), &config, &sk_var, &nonce_var)?;
        let zero_var = FpVar::new_constant(cs.clone(), Fr::zero())?;
        let leaf_var = poseidon_hash_var(cs.clone(), &config, &zero_var, &commitment_var)?;

        // ══════════════════════════════════════════════════════════════════
        // CONSTRAINT 2: Merkle Path Verification
        // For each level, hash (current, sibling) or (sibling, current)
        // based on the path bit, producing the parent node.
        // After all levels, the result must equal the public root.
        // ══════════════════════════════════════════════════════════════════

        let mut current = leaf_var;

        for i in 0..tree_depth {
            let sibling_var = FpVar::new_witness(cs.clone(), || {
                merkle_siblings_val[i].ok_or(SynthesisError::AssignmentMissing)
            })?;

            let path_bit = Boolean::new_witness(cs.clone(), || {
                path_indices_val[i].ok_or(SynthesisError::AssignmentMissing)
            })?;

            // path_bit = false (left child):  left = current,  right = sibling
            // path_bit = true  (right child): left = sibling, right = current
            let left = FpVar::conditionally_select(&path_bit, &sibling_var, &current)?;
            let right = FpVar::conditionally_select(&path_bit, &current, &sibling_var)?;

            current = poseidon_hash_var(cs.clone(), &config, &left, &right)?;
        }

        // Enforce: reconstructed root == public merkle_root
        current.enforce_equal(&root_var)?;

        // ══════════════════════════════════════════════════════════════════
        // CONSTRAINT 3: Nullifier Derivation
        // nullifier == Poseidon(sk, challenge)
        // Ensures the proof is bound to this challenge, and the same
        // key + challenge always produces the same nullifier (replay
        // detection), while different challenges produce different
        // nullifiers (unlinkability).
        // ══════════════════════════════════════════════════════════════════

        let computed_nullifier = poseidon_hash_var(cs.clone(), &config, &sk_var, &challenge_var)?;
        computed_nullifier.enforce_equal(&nullifier_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::{poseidon_config, poseidon_hash};
    use crate::tree::MerkleTree;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_circuit_satisfiability_valid_witness() {
        let config = poseidon_config();
        let mut rng = ark_std::test_rng();

        // Build a small tree with 4 dummy leaves + 1 user leaf
        let mut tree = MerkleTree::with_config(config.clone());
        for _ in 0..4 {
            let dummy_sk = Fr::rand(&mut rng);
            let dummy_nonce = Fr::rand(&mut rng);
            let commitment = poseidon_hash(&config, &[dummy_sk, dummy_nonce]);
            tree.insert(commitment).unwrap();
        }

        // User's credentials
        let sk = Fr::rand(&mut rng);
        let nonce = Fr::rand(&mut rng);
        let commitment = poseidon_hash(&config, &[sk, nonce]);
        let user_index = tree.insert(commitment).unwrap();
        let root = tree.root().unwrap();
        let proof = tree.generate_inclusion_proof(user_index).unwrap();

        // Challenge and nullifier
        let challenge = Fr::rand(&mut rng);
        let nullifier = poseidon_hash(&config, &[sk, challenge]);

        // Build circuit
        let circuit = ObscuraCircuit {
            poseidon_config: config,
            tree_depth: proof.siblings.len(),
            merkle_root: Some(root),
            nullifier: Some(nullifier),
            secret_key: Some(sk),
            nonce: Some(nonce),
            challenge: Some(challenge),
            merkle_siblings: proof.siblings.iter().map(|s| Some(*s)).collect(),
            path_indices: proof.path_indices.iter().map(|b| Some(*b)).collect(),
        };

        // Check constraint satisfaction
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "Valid witness must satisfy constraints");
        println!("Circuit constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_circuit_rejects_wrong_nullifier() {
        let config = poseidon_config();
        let mut rng = ark_std::test_rng();

        let mut tree = MerkleTree::with_config(config.clone());
        let sk = Fr::rand(&mut rng);
        let nonce = Fr::rand(&mut rng);
        let commitment = poseidon_hash(&config, &[sk, nonce]);
        tree.insert(commitment).unwrap();
        let root = tree.root().unwrap();
        let proof = tree.generate_inclusion_proof(0).unwrap();

        let challenge = Fr::rand(&mut rng);
        let wrong_nullifier = Fr::rand(&mut rng); // wrong!

        let circuit = ObscuraCircuit {
            poseidon_config: config,
            tree_depth: proof.siblings.len(),
            merkle_root: Some(root),
            nullifier: Some(wrong_nullifier),
            secret_key: Some(sk),
            nonce: Some(nonce),
            challenge: Some(challenge),
            merkle_siblings: proof.siblings.iter().map(|s| Some(*s)).collect(),
            path_indices: proof.path_indices.iter().map(|b| Some(*b)).collect(),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Wrong nullifier must NOT satisfy constraints");
    }

    #[test]
    fn test_circuit_rejects_wrong_root() {
        let config = poseidon_config();
        let mut rng = ark_std::test_rng();

        let mut tree = MerkleTree::with_config(config.clone());
        let sk = Fr::rand(&mut rng);
        let nonce = Fr::rand(&mut rng);
        let commitment = poseidon_hash(&config, &[sk, nonce]);
        tree.insert(commitment).unwrap();
        let _root = tree.root().unwrap();
        let proof = tree.generate_inclusion_proof(0).unwrap();

        let challenge = Fr::rand(&mut rng);
        let nullifier = poseidon_hash(&config, &[sk, challenge]);
        let wrong_root = Fr::rand(&mut rng); // wrong!

        let circuit = ObscuraCircuit {
            poseidon_config: config,
            tree_depth: proof.siblings.len(),
            merkle_root: Some(wrong_root),
            nullifier: Some(nullifier),
            secret_key: Some(sk),
            nonce: Some(nonce),
            challenge: Some(challenge),
            merkle_siblings: proof.siblings.iter().map(|s| Some(*s)).collect(),
            path_indices: proof.path_indices.iter().map(|b| Some(*b)).collect(),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Wrong root must NOT satisfy constraints");
    }
}
