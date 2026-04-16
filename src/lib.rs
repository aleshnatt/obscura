//! # Obscura — Anonymous WebAuthn Credential Protocol
//!
//! A privacy-preserving, ZK-augmented FIDO2/WebAuthn authentication engine
//! with Groth16 proofs over BN254 via the arkworks cryptographic library.
//!
//! ## Modules
//!
//! - [`error`]: Protocol error taxonomy.
//! - [`poseidon`]: SNARK-friendly Poseidon hash for BN254 Fr.
//! - [`tree`]: Poseidon-based binary Merkle tree (anonymity set).
//! - [`circuit`]: R1CS circuit for the authentication relation R_auth.
//! - [`protocol`]: Groth16 prover, verifier, and trusted setup.

pub mod error;
pub mod poseidon;
pub mod tree;
pub mod circuit;
pub mod protocol;
