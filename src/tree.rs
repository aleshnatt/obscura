//! Merkle authorization set for credential commitments.
//!
//! This module implements a SHAKE-256 binary Merkle tree over 32-byte
//! credential commitment hashes. It is designed to detect tampering with
//! inclusion paths when the verifier obtains the root from a trusted source. It
//! does not hide the tree size, protect against an adversary-chosen root, or
//! provide side-channel resistance for local proof processing.

use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::error::ProtocolError;

/// Domain separator for leaf hashing.
const LEAF_DOMAIN: &[u8] = b"COM_DOM";

/// Domain separator for internal node hashing.
const NODE_DOMAIN: &[u8] = b"NODE_DOM";

/// Zero hash (32 bytes of zeros) used for padding empty leaf slots.
const ZERO_HASH: [u8; 32] = [0u8; 32];

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

/// A binary Merkle tree over SHAKE-256-hashed 32-byte digests.
///
/// The tree accumulates credential commitments into a compact authorization
/// root. It enforces deterministic domain-separated hashing for leaves and
/// internal nodes, but it does not authenticate the root for callers. Verifiers
/// must obtain the root from a trusted channel before accepting membership
/// proofs.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Raw leaf values (commitment hashes) as inserted by callers.
    leaves: Vec<[u8; 32]>,
    /// Flattened binary tree array. Index 0 is unused (sentinel), index 1 is root.
    nodes: Vec<[u8; 32]>,
}

/// Merkle inclusion proof for a credential commitment.
///
/// Verifying this proof against a trusted root confirms that the committed
/// credential was included in the authorization set used to build that root.
/// The proof reveals the path length and left/right position bits. Callers must
/// reject roots supplied by adversaries, because membership is only meaningful
/// relative to the chosen root.
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

/// Smallest power of two ≥ n.
fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        1
    } else {
        n.next_power_of_two()
    }
}

impl MerkleTree {
    /// Create a new, empty Merkle tree.
    ///
    /// # Security
    ///
    /// An empty tree has no authorization root. Callers must insert at least
    /// one credential commitment before requesting a root or proof.
    pub fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            nodes: Vec::new(),
        }
    }

    /// Inserts a credential commitment hash into the tree.
    ///
    /// # Errors
    ///
    /// This function currently has no error path and returns `Ok(index)` for
    /// API consistency with fallible tree operations.
    ///
    /// # Security
    ///
    /// The leaf should be the output of the crate's credential commitment
    /// function. Inserting arbitrary values is allowed but only proves
    /// membership of those values.
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<usize, ProtocolError> {
        let index = self.leaves.len();
        self.leaves.push(leaf);
        self.nodes.clear();
        Ok(index)
    }

    /// Returns the inserted raw leaf values.
    ///
    /// # Security
    ///
    /// The returned values are public commitments, but they may still be
    /// linkable across authorization sets.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Returns the number of inserted leaves.
    ///
    /// # Security
    ///
    /// The count can reveal authorization-set size. Do not expose it where set
    /// size is intended to remain private.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
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

    /// Computes and returns the Merkle root.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyTree`] if no leaves have been inserted.
    ///
    /// # Security
    ///
    /// The returned root must be distributed through an authenticated channel.
    /// A verifier that accepts an adversary-controlled root accepts membership
    /// in the adversary's authorization set.
    pub fn root(&mut self) -> Result<[u8; 32], ProtocolError> {
        if self.leaves.is_empty() {
            return Err(ProtocolError::EmptyTree);
        }
        if self.nodes.is_empty() {
            self.build_tree()?;
        }
        Ok(self.nodes[1])
    }

    /// Returns the depth of the padded binary tree.
    ///
    /// # Security
    ///
    /// Tree depth reveals a bound on the number of inserted commitments.
    pub fn depth(&self) -> usize {
        if self.leaves.is_empty() {
            return 0;
        }
        next_power_of_two(self.leaves.len()).trailing_zeros() as usize
    }

    /// Generates a Merkle inclusion proof for the leaf at `leaf_index`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLeafIndex`] if `leaf_index` is outside
    /// the inserted leaf range. Returns [`ProtocolError::EmptyTree`] if the
    /// tree must be built but contains no leaves.
    ///
    /// # Security
    ///
    /// The proof is bound to the root currently computed by this tree. Callers
    /// must send or store the matching root with the proof.
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
            let is_left_child = current_index % 2 == 0;
            let sibling_index = if is_left_child {
                current_index + 1
            } else {
                current_index - 1
            };

            siblings.push(self.nodes[sibling_index]);
            path_indices.push(!is_left_child);

            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            siblings,
            path_indices,
            root: self.nodes[1],
        })
    }

    /// Verifies a Merkle inclusion proof against its embedded root.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural
    /// checks are performed before any arithmetic. Malformed input is
    /// rejected with `false` rather than panicking.
    ///
    /// # Security
    ///
    /// A `true` result only means the path reconstructs `proof.root`. The caller
    /// must compare that root with an authenticated authorization root before
    /// accepting membership.
    pub fn verify_inclusion_proof(proof: &MerkleProof) -> bool {
        if proof.siblings.len() != proof.path_indices.len() {
            return false;
        }

        let mut current = hash_leaf(&proof.leaf);

        for (sibling, is_right_child) in proof.siblings.iter().zip(&proof.path_indices) {
            if !is_right_child {
                current = hash_node(&current, sibling);
            } else {
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
        proof.leaf = random_leaf(99); // simulate a substituted commitment leaf
        assert!(!MerkleTree::verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_malformed_proof_lengths_rejected() {
        let mut tree = MerkleTree::new();
        for i in 0..4 {
            tree.insert(random_leaf(i + 30)).unwrap();
        }

        let mut proof = tree.generate_inclusion_proof(0).unwrap();
        proof.path_indices.pop(); // simulate a truncated network payload

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
