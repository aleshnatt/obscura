# Obscura

Obscura provides lattice-based credential authorization with Merkle membership proofs for applications that need scoped credential checks without exposing the credential secret.

[![Crates.io](https://img.shields.io/crates/v/obscura.svg)](https://crates.io/crates/obscura) [![docs.rs](https://docs.rs/obscura/badge.svg)](https://docs.rs/obscura) [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## What This Crate Does

Obscura models a credential as Module-LWE-style key material. The public key is committed into a SHAKE-256 Merkle tree, while the secret key remains with the credential holder. A verifier accepts authorization only when a proof binds the public key, the Merkle root, a verifier-chosen scope, and a scope-bound nullifier.

The crate is useful for systems that need a compact authorization root and a public verification artifact. The Merkle tree represents the credential set, the nullifier supports replay or double-use detection within a scope, and the proof relation checks that the response is consistent with the committed key material.

The implementation exposes a high-level API for generating parameters, creating credential keys, building the authorization set, producing a proof, verifying a proof, and serializing proof objects for transport.

## Security Notice
Known limitations:
- Polynomial arithmetic, coefficient comparisons, and norm checks are not constant-time.
- The proof construction and parameter choices require independent cryptographic review before deployment.
- Merkle roots and parameter seeds must be authenticated by the application; the crate does not establish trust in those values.
- Serialized proofs are public verification artifacts, but nullifiers and Merkle paths can be linkable across repeated use.

## Quick Start

```rust
use rand::rngs::OsRng;
use obscura::mlwe::MlweParams;
use obscura::protocol::{KeyPair, Prover, PublicInputs, Verifier};
use obscura::tree::MerkleTree;

fn main() -> Result<(), obscura::error::ProtocolError> {
    let mut rng = OsRng;
    let params = MlweParams::generate(&mut rng);
    let mut tree = MerkleTree::new();
    let user = KeyPair::generate(&params, &mut rng);
    let index = tree.insert(user.commitment())?;
    let root = tree.root()?;
    let path = tree.generate_inclusion_proof(index)?;
    let scope = b"session-challenge".to_vec();
    let inputs = PublicInputs { merkle_root: root, scope: scope.clone(), nullifier: user.nullifier(&scope) };
    let proof = Prover::generate_proof(&params, &user, &path, &inputs, &mut rng)?;
    assert!(Verifier::verify_proof(&params, &proof, &inputs)?);
    Ok(())
}
```

## Parameter Sets

| Name | Security Target | Key Fields |
| --- | --- | --- |
| `default` | targets ~128-bit classical security, subject to independent review | `n = 256`, `q = 8,380,417`, `k = 2`, `eta = 2`, `tau = 39` |

## Building and Testing

```sh
cargo build --release
cargo test --all-features
cargo test --doc
```

## License

MIT OR Apache-2.0.
