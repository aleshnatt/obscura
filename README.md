# Obscura

Obscura is a Rust library for lattice-based credential authorization. It combines Module-LWE-style key material, Fiat-Shamir-style transcript challenges, SHAKE-256 commitments, and a Merkle membership path over credential commitments.

The API is designed for applications that need credential commitments, scoped nullifiers, and verifiable membership against a compact Merkle root.

## Status

- Library-first Rust crate.
- SHAKE-256 domain-separated commitments and Merkle nodes.
- Module-LWE-style key generation and proof relation checks.
- JSON proof serialization helpers.
- End-to-end quickstart under `examples/quickstart.rs`.

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
    let user_index = tree.insert(user.commitment())?;
    let root = tree.root()?;
    let merkle_proof = tree.generate_inclusion_proof(user_index)?;

    let scope = b"session-challenge".to_vec();
    let public_inputs = PublicInputs {
        merkle_root: root,
        scope: scope.clone(),
        nullifier: user.nullifier(&scope),
    };

    let proof = Prover::generate_proof(
        &params,
        &user,
        &merkle_proof,
        &public_inputs,
        &mut rng,
    )?;

    assert!(Verifier::verify_proof(&params, &proof, &public_inputs)?);
    Ok(())
}
```

Run the bundled quickstart:

```sh
cargo run --example quickstart
```

## Verification Gates

Before publishing a release, run:

```sh
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --list
cargo publish --dry-run
```

## License

MIT
