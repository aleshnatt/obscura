//! # Obscura Protocol — Merkle Tree (Anonymity Set)
//!
//! Poseidon-based binary Merkle tree over BN254 scalar field elements.
//!
//! Each leaf is a Poseidon commitment to a user's credential. The tree
//! root serves as a compact, tamper-evident digest of the anonymity set.
//!
//! ## SNARK-Friendly Design
//!
//! Unlike SHA-256 Merkle trees, this tree uses Poseidon hashing which
//! costs only ~300 R1CS constraints per node — enabling efficient
//! in-circuit verification of inclusion proofs.
//!
//! ## Domain Separation
//!
//! - **Leaf hash**: `Poseidon(0, leaf_data)` — the zero prefix domain-separates
//!   leaves from internal nodes, preventing second-preimage attacks.
//! - **Internal node hash**: `Poseidon(left, right)` — standard 2-to-1 hash.

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::error::ProtocolError;
use crate::poseidon::{poseidon_config, poseidon_hash, poseidon_hash_two};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

// ─── Structs ─────────────────────────────────────────────────────────────────

/// A binary Merkle tree over Poseidon-hashed BN254 field elements.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Raw leaf values (commitments) as inserted by callers.
    pub leaves: Vec<Fr>,
    /// Flattened binary tree array. Index 0 is unused (sentinel), index 1 is root.
    pub nodes: Vec<Fr>,
    /// Cached Poseidon configuration (shared across all hash operations).
    config: PoseidonConfig<Fr>,
}

/// A Merkle inclusion proof for a specific leaf.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The raw leaf value whose membership is being proven.
    pub leaf: Fr,
    /// Sibling hashes along the path from the leaf to the root.
    pub siblings: Vec<Fr>,
    /// Direction at each level: false = left child, true = right child.
    pub path_indices: Vec<bool>,
    /// The Merkle root computed at proof-generation time.
    pub root: Fr,
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/// Domain-separated leaf hash: `Poseidon(0, leaf_data)`.
fn hash_leaf(config: &PoseidonConfig<Fr>, data: &Fr) -> Fr {
    poseidon_hash(config, &[Fr::zero(), *data])
}

/// Internal node hash: `Poseidon(left, right)`.
fn hash_node(config: &PoseidonConfig<Fr>, left: &Fr, right: &Fr) -> Fr {
    poseidon_hash_two(config, left, right)
}

/// Smallest power of two ≥ n.
fn next_power_of_two(n: usize) -> usize {
    if n == 0 { 1 } else { n.next_power_of_two() }
}

// ─── MerkleTree Implementation ───────────────────────────────────────────────

impl MerkleTree {
    /// Create a new, empty Merkle tree with standard Poseidon parameters.
    pub fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            nodes: Vec::new(),
            config: poseidon_config(),
        }
    }

    /// Create a Merkle tree with a given Poseidon configuration.
    pub fn with_config(config: PoseidonConfig<Fr>) -> Self {
        MerkleTree {
            leaves: Vec::new(),
            nodes: Vec::new(),
            config,
        }
    }

    /// Return a reference to the Poseidon configuration used by this tree.
    pub fn config(&self) -> &PoseidonConfig<Fr> {
        &self.config
    }

    /// Insert a leaf (commitment) into the tree.
    pub fn insert(&mut self, leaf: Fr) -> Result<usize, ProtocolError> {
        let index = self.leaves.len();
        self.leaves.push(leaf);
        self.nodes.clear(); // invalidate cached tree
        Ok(index)
    }

    /// Build the flattened binary tree array from current leaves.
    fn build_tree(&mut self) -> Result<(), ProtocolError> {
        if self.leaves.is_empty() {
            return Err(ProtocolError::EmptyTree);
        }

        let num_leaves = next_power_of_two(self.leaves.len());
        let total_nodes = 2 * num_leaves;

        self.nodes = vec![Fr::zero(); total_nodes];

        // Hash leaves into the second half of the array.
        let zero_leaf = Fr::zero();
        for i in 0..num_leaves {
            let leaf_data = if i < self.leaves.len() {
                &self.leaves[i]
            } else {
                &zero_leaf
            };
            self.nodes[num_leaves + i] = hash_leaf(&self.config, leaf_data);
        }

        // Build internal nodes bottom-up.
        for i in (1..num_leaves).rev() {
            self.nodes[i] = hash_node(
                &self.config,
                &self.nodes[2 * i],
                &self.nodes[2 * i + 1],
            );
        }

        Ok(())
    }

    /// Compute and return the Merkle root.
    pub fn root(&mut self) -> Result<Fr, ProtocolError> {
        if self.leaves.is_empty() {
            return Err(ProtocolError::EmptyTree);
        }
        if self.nodes.is_empty() {
            self.build_tree()?;
        }
        Ok(self.nodes[1])
    }

    /// Return the depth of the tree.
    pub fn depth(&self) -> usize {
        if self.leaves.is_empty() {
            return 0;
        }
        let num_leaves = next_power_of_two(self.leaves.len());
        (num_leaves as f64).log2() as usize
    }

    /// Generate a Merkle inclusion proof for the leaf at `leaf_index`.
    pub fn generate_inclusion_proof(
        &mut self,
        leaf_index: usize,
    ) -> Result<MerkleProof, ProtocolError> {
        if leaf_index >= self.leaves.len() {
            return Err(ProtocolError::InvalidLeafIndex {
                index: leaf_index,
                total_leaves: self.leaves.len(),
            });
        }

        if self.nodes.is_empty() {
            self.build_tree()?;
        }

        let num_leaves = next_power_of_two(self.leaves.len());
        let depth = (num_leaves as f64).log2() as usize;

        let mut siblings = Vec::with_capacity(depth);
        let mut path_indices = Vec::with_capacity(depth);
        let mut current_index = num_leaves + leaf_index;

        for _ in 0..depth {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            siblings.push(self.nodes[sibling_index]);
            path_indices.push(current_index % 2 != 0); // true if right child

            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            siblings,
            path_indices,
            root: self.nodes[1],
        })
    }

    /// Verify a Merkle inclusion proof (static utility).
    pub fn verify_inclusion_proof(config: &PoseidonConfig<Fr>, proof: &MerkleProof) -> bool {
        let mut current = hash_leaf(config, &proof.leaf);

        for i in 0..proof.siblings.len() {
            if !proof.path_indices[i] {
                // Current was left child.
                current = hash_node(config, &current, &proof.siblings[i]);
            } else {
                // Current was right child.
                current = hash_node(config, &proof.siblings[i], &current);
            }
        }

        current == proof.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_single_leaf_tree() {
        let mut tree = MerkleTree::new();
        let mut rng = ark_std::test_rng();
        let leaf = Fr::rand(&mut rng);
        tree.insert(leaf).unwrap();

        let root = tree.root().unwrap();
        assert_ne!(root, Fr::zero());

        let proof = tree.generate_inclusion_proof(0).unwrap();
        assert!(MerkleTree::verify_inclusion_proof(tree.config(), &proof));
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = MerkleTree::new();
        let mut rng = ark_std::test_rng();
        for _ in 0..8 {
            tree.insert(Fr::rand(&mut rng)).unwrap();
        }

        for i in 0..8 {
            let proof = tree.generate_inclusion_proof(i).unwrap();
            assert!(MerkleTree::verify_inclusion_proof(tree.config(), &proof));
        }
    }

    #[test]
    fn test_non_power_of_two_padding() {
        let mut tree = MerkleTree::new();
        let mut rng = ark_std::test_rng();
        for _ in 0..5 {
            tree.insert(Fr::rand(&mut rng)).unwrap();
        }

        let proof = tree.generate_inclusion_proof(4).unwrap();
        assert!(MerkleTree::verify_inclusion_proof(tree.config(), &proof));
    }

    #[test]
    fn test_invalid_proof_detection() {
        let mut tree = MerkleTree::new();
        let mut rng = ark_std::test_rng();
        for _ in 0..4 {
            tree.insert(Fr::rand(&mut rng)).unwrap();
        }

        let mut proof = tree.generate_inclusion_proof(0).unwrap();
        proof.leaf = Fr::rand(&mut rng); // tamper
        assert!(!MerkleTree::verify_inclusion_proof(tree.config(), &proof));
    }

    #[test]
    fn test_empty_tree_error() {
        let mut tree = MerkleTree::new();
        assert!(matches!(tree.root(), Err(ProtocolError::EmptyTree)));
    }

    #[test]
    fn test_out_of_bounds_index() {
        let mut tree = MerkleTree::new();
        let mut rng = ark_std::test_rng();
        tree.insert(Fr::rand(&mut rng)).unwrap();
        assert!(matches!(
            tree.generate_inclusion_proof(5),
            Err(ProtocolError::InvalidLeafIndex { .. })
        ));
    }
}
