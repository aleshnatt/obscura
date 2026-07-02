//! # Obscura
//!
//! Obscura provides lattice-based credential authorization with Merkle membership
//! proofs and scope-bound nullifiers.
//!
//!
//! # Quick Start
//!
//! ```rust
//! use rand::rngs::OsRng;
//! use obscura::mlwe::MlweParams;
//! use obscura::protocol::{KeyPair, Prover, PublicInputs, Verifier};
//! use obscura::tree::MerkleTree;
//!
//! # fn main() -> Result<(), obscura::error::ProtocolError> {
//! let mut rng = OsRng;
//! let params = MlweParams::generate(&mut rng);
//! let mut tree = MerkleTree::new();
//! let user = KeyPair::generate(&params, &mut rng);
//! let index = tree.insert(user.commitment())?;
//! let root = tree.root()?;
//! let proof_path = tree.generate_inclusion_proof(index)?;
//! let scope = b"session".to_vec();
//! let inputs = PublicInputs { merkle_root: root, scope: scope.clone(), nullifier: user.nullifier(&scope) };
//! let proof = Prover::generate_proof(&params, &user, &proof_path, &inputs, &mut rng)?;
//! assert!(Verifier::verify_proof(&params, &proof, &inputs)?);
//! # Ok(()) }
//! ```
//!
//! # Architecture
//!
//! The [`poly`] module defines arithmetic over `R_q`, [`mlwe`] builds public
//! parameters and credential key material, [`tree`] maintains the Merkle
//! authorization set, and [`zk_auth`] contains the Fiat-Shamir-style proof
//! relation. The [`protocol`] module exposes the high-level API used by
//! applications, while [`error`] provides the shared error taxonomy.

pub mod error;
pub mod mlwe;
pub mod poly;
pub mod protocol;
pub mod tree;
pub mod zk_auth;
