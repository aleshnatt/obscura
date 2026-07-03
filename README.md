# Obscura

Obscura provides lattice-based credential authorization with Merkle membership proofs for applications that need scoped credential checks without exposing the credential secret.

[![Crates.io](https://img.shields.io/crates/v/obscura.svg)](https://crates.io/crates/obscura) [![docs.rs](https://docs.rs/obscura/badge.svg)](https://docs.rs/obscura) [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## What This Crate Does

Obscura models a credential as Module-LWE-style key material. The public key is committed into a SHAKE-256 Merkle tree, while the secret key remains with the credential holder. A verifier accepts authorization only when a proof binds the credential commitment, an authenticated Merkle root, a verifier-chosen scope, and a scope-bound nullifier.

The crate is useful for systems that need a compact authorization root and a public verification artifact. The Merkle tree represents the credential set, the nullifier supports replay or double-use detection within a scope, and the proof relation checks that the response is consistent with the committed key material.

The implementation exposes a high-level API for generating parameters, creating credential keys, building the authorization set, producing a proof, verifying a proof, and serializing proof objects for transport.

## Security Notice
Known limitations:
- Polynomial arithmetic and norm-bound checks use fixed-dimension loops and full-scan comparisons for the proof paths in this crate. The implementation has not received an external side-channel audit.
- The proof construction and parameter choices require independent cryptographic review before deployment.
- Verifier APIs require an `AuthenticatedRoot` bound to the MLWE parameter digest. Applications still need to authenticate the root and parameter source before constructing that wrapper.
- Serialized proofs no longer expose the public key or Merkle path as plaintext fields. Nullifiers remain public and scope-bound with `SHAKE-256("NUL_DOM" || s || scope)` for replay detection within the selected scope.

## Quick Start

```rust
use rand::rngs::OsRng;
use obscura::mlwe::MlweParams;
use obscura::protocol::{AuthenticatedRoot, KeyPair, Prover, PublicInputs, Verifier};
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
    let authenticated_root = AuthenticatedRoot::from_trusted_source(root, &params);
    let inputs = PublicInputs::new_authenticated(authenticated_root, scope.clone(), user.nullifier(&scope));
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
