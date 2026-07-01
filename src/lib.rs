//! # Obscura
//!
//! A Rust library for lattice-based credential authorization using Module-LWE-style
//! key material, SHAKE-256 commitments, Merkle membership, and Fiat-Shamir-style
//! transcript challenges.
//!
//! ## Modules
//!
//! - [`error`]: Protocol error taxonomy.
//! - [`poly`]: Polynomial arithmetic in R_q = Z_q\[X\]/(X^256 + 1).
//! - [`mlwe`]: Module-LWE key generation and challenge sampling.
//! - [`tree`]: SHAKE-256-based binary Merkle tree (anonymity set).
//! - [`zk_auth`]: Lattice-based ZK authorization proof/verify (Fiat-Shamir with Aborts).
//! - [`protocol`]: High-level prover, verifier, and key management API.

pub mod error;
pub mod mlwe;
pub mod poly;
pub mod protocol;
pub mod tree;
pub mod zk_auth;
