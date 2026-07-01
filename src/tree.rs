//! # Obscura Protocol — Merkle Tree (Anonymity Set)
//!
//! SHAKE-256-based binary Merkle tree over 32-byte hash digests.
//!
//! Each leaf is the commitment hash of a user's MLWE public key. The tree
//! root serves as a compact, tamper-evident digest of the anonymity set.
//!
//! ## Post-Quantum Design
//!
//! This tree uses SHAKE-256 (a member of the SHA-3 family) which provides
//! quantum-resistant collision resistance. The hash function is a standard
//! XOF (Extendable Output Function) from NIST FIPS 202.
//!
//! ## Domain Separation
//!
//! - **Leaf hash**: `SHAKE-256("COM_DOM" ∥ leaf_data)` — the domain prefix
//!   separates leaves from internal nodes, preventing second-preimage attacks.
//! - **Internal node hash**: `SHAKE-256("NODE_DOM" ∥ left ∥ right)` — standard
//!   2-to-1 hash with its own domain separator.

use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::error::ProtocolError;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Domain separator for leaf hashing.
const LEAF_DOMAIN: &[u8] = b"COM_DOM";

/// Domain separator for internal node hashing.
const NODE_DOMAIN: &[u8] = b"NODE_DOM";

/// Zero hash (32 bytes of zeros) used for padding empty leaf slots.
const ZERO_HASH: [u8; 32] = [0u8; 32];

// ─── Hash Functions ──────────────────────────────────────────────────────────

/// Domain-separated leaf hash: SHAKE-256("COM_DOM" ∥ leaf_data), 32 bytes.
fn hash_leaf(data: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(LEAF_DOMAIN);
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

/// Internal node hash: SHAKE-256("NODE_DOM" ∥ left ∥ right), 32 bytes.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

// ─── Structs ─────────────────────────────────────────────────────────────────

/// A binary Merkle tree over SHAKE-256-hashed 32-byte digests.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Raw leaf values (commitment hashes) as inserted by callers.
    pub leaves: Vec<[u8; 32]>,
    /// Flattened binary tree array. Index 0 is unused (sentinel), index 1 is root.
    nodes: Vec<[u8; 32]>,
}

/// A Merkle inclusion proof for a specific leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The raw leaf value whose membership is being proven.
    pub leaf: [u8; 32],
    /// Sibling hashes along the path from the leaf to the root.
    pub siblings: Vec<[u8; 32]>,
    /// Direction at each level: false = left child, true = right child.
    pub path_indices: Vec<bool>,
    /// The Merkle root computed at proof-generation time.
    pub root: [u8; 32],
}

// ─── Helper ──────────────────────────────────────────────────────────────────

/// Smallest power of two ≥ n.
fn next_power_of_two(n: usize) -> usize {
    if n == 0 { 1 } else { n.next_power_of_two() }
}

// ─── MerkleTree Implementation ───────────────────────────────────────────────

impl MerkleTree {
    /// Create a new, empty Merkle tree.
    pub fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            nodes: Vec::new(),
        }
    }

    /// Insert a leaf (commitment hash) into the tree.
    ///
    /// The leaf should be the output of `commitment_hash()` from the MLWE module.
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<usize, ProtocolError> {
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

        self.nodes = vec![ZERO_HASH; total_nodes];

        // Hash leaves into the second half of the array.
        for i in 0..num_leaves {
            let leaf_data = if i < self.leaves.len() {
                &self.leaves[i]
            } else {
                &ZERO_HASH
            };
            self.nodes[num_leaves + i] = hash_leaf(leaf_data);
        }

        // Build internal nodes bottom-up.
        for i in (1..num_leaves).rev() {
            self.nodes[i] = hash_node(&self.nodes[2 * i], &self.nodes[2 * i + 1]);
        }

        Ok(())
    }

    /// Compute and return the Merkle root as a 32-byte hash.
    pub fn root(&mut self) -> Result<[u8; 32], ProtocolError> {
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
        next_power_of_two(self.leaves.len()).trailing_zeros() as usize
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
        let depth = num_leaves.trailing_zeros() as usize;

        let mut siblings = Vec::with_capacity(depth);
        let mut path_indices = Vec::with_capacity(depth);
        let mut current_index = num_leaves + leaf_index;

        for _ in 0..depth {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            siblings.push(self.nodes[sibling_index]);
            path_indices.push(!current_index.is_multiple_of(2)); // true if right child

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
    ///
    /// Recomputes the root from the leaf and sibling path, then checks
    /// if it matches the claimed root in the proof.
    pub fn verify_inclusion_proof(proof: &MerkleProof) -> bool {
        if proof.siblings.len() != proof.path_indices.len() {
            return false;
        }

        let mut current = hash_leaf(&proof.leaf);

        for (sibling, is_right_child) in proof.siblings.iter().zip(&proof.path_indices) {
            if !is_right_child {
                // Current was left child.
                current = hash_node(&current, sibling);
            } else {
                // Current was right child.
                current = hash_node(sibling, &current);
            }
        }

        current == proof.root
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_leaf(seed: u8) -> [u8; 32] {
        let mut leaf = [0u8; 32];
        for (i, byte) in leaf.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        leaf
    }

    #[test]
    fn test_single_leaf_tree() {
        let mut tree = MerkleTree::new();
        let leaf = random_leaf(1);
        tree.insert(leaf).unwrap();

        let root = tree.root().unwrap();
        assert_ne!(root, ZERO_HASH);

        let proof = tree.generate_inclusion_proof(0).unwrap();
        assert!(MerkleTree::verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = MerkleTree::new();
        for i in 0..8 {
            tree.insert(random_leaf(i)).unwrap();
        }

        for i in 0..8 {
            let proof = tree.generate_inclusion_proof(i).unwrap();
            assert!(
                MerkleTree::verify_inclusion_proof(&proof),
                "Proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn test_non_power_of_two_padding() {
        let mut tree = MerkleTree::new();
        for i in 0..5 {
            tree.insert(random_leaf(i + 10)).unwrap();
        }

        let proof = tree.generate_inclusion_proof(4).unwrap();
        assert!(MerkleTree::verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_invalid_proof_detection() {
        let mut tree = MerkleTree::new();
        for i in 0..4 {
            tree.insert(random_leaf(i + 20)).unwrap();
        }

        let mut proof = tree.generate_inclusion_proof(0).unwrap();
        proof.leaf = random_leaf(99); // tamper
        assert!(!MerkleTree::verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_malformed_proof_lengths_rejected() {
        let mut tree = MerkleTree::new();
        for i in 0..4 {
            tree.insert(random_leaf(i + 30)).unwrap();
        }

        let mut proof = tree.generate_inclusion_proof(0).unwrap();
        proof.path_indices.pop();

        assert!(!MerkleTree::verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_empty_tree_error() {
        let mut tree = MerkleTree::new();
        assert!(matches!(tree.root(), Err(ProtocolError::EmptyTree)));
    }

    #[test]
    fn test_out_of_bounds_index() {
        let mut tree = MerkleTree::new();
        tree.insert(random_leaf(0)).unwrap();
        assert!(matches!(
            tree.generate_inclusion_proof(5),
            Err(ProtocolError::InvalidLeafIndex { .. })
        ));
    }

    #[test]
    fn test_domain_separation() {
        // A leaf hash and an internal node hash of the same data should differ.
        let data = [42u8; 32];
        let leaf_h = hash_leaf(&data);
        let node_h = hash_node(&data, &data);
        assert_ne!(
            leaf_h, node_h,
            "Leaf and node hashes of same data must differ (domain separation)"
        );
    }
}
