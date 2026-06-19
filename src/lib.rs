//! # Obscura — Post-Quantum Anonymous WebAuthn Credential Protocol
//!
//! A privacy-preserving, lattice-based Zero-Knowledge authentication engine
//! using Module-LWE proofs via the Fiat-Shamir with Aborts paradigm.
//!
//! ## Post-Quantum Security
//!
//! This protocol is resistant to quantum attacks. Security is based on the
//! hardness of Module-LWE and Module-SIS in the Quantum Random Oracle Model
//! (QROM), providing ≥128-bit classical and ≥64-bit quantum security (NIST
//! Category 1 equivalent).
//!
//! ## Modules
//!
//! - [`error`]: Protocol error taxonomy.
//! - [`poly`]: Polynomial arithmetic in R_q = ℤ_q[X]/(X^256 + 1).
//! - [`mlwe`]: Module-LWE key generation and challenge sampling.
//! - [`tree`]: SHAKE-256-based binary Merkle tree (anonymity set).
//! - [`zk_auth`]: Lattice-based ZK authorization proof/verify (Fiat-Shamir with Aborts).
//! - [`protocol`]: High-level prover, verifier, and key management API.

pub mod error;
pub mod poly;
pub mod mlwe;
pub mod tree;
pub mod zk_auth;
pub mod protocol;
