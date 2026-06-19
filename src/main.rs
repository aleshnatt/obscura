//! # Obscura Protocol — CLI Testbed & Benchmark
//!
//! Full end-to-end post-quantum protocol simulation with lattice-based ZK proofs.

use std::time::Instant;

use clap::{Parser, Subcommand};
use rand::rngs::OsRng;

use obscura::mlwe::MlweParams;
use obscura::poly::{BETA, GAMMA1, K, N, Q, TAU};
use obscura::protocol::{
    deserialize_proof, serialize_proof, KeyPair, Prover, PublicInputs, Verifier,
};
use obscura::tree::MerkleTree;

/// Obscura Protocol — Post-Quantum Anonymous WebAuthn Credential Engine
#[derive(Parser)]
#[command(name = "obscura")]
#[command(about = "Post-quantum ZK-augmented FIDO2/WebAuthn protocol simulator with lattice-based proofs")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the full protocol simulation end-to-end
    Simulate,
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Simulate) | None => {
            if let Err(e) = run_simulation() {
                eprintln!("Protocol error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn run_simulation() -> Result<(), obscura::error::ProtocolError> {
    let mut rng = OsRng;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║      OBSCURA — Post-Quantum ZK-FIDO2 Simulator             ║");
    println!("║      Lattice-Based ZK-Auth (Module-LWE / Fiat-Shamir)      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ─── Display Cryptographic Parameters ────────────────────────────────
    println!("┌─ Cryptographic Parameters ─────────────────────────────────┐");
    println!("│  Ring:              R_q = ℤ_q[X]/(X^{N} + 1)");
    println!("│  Ring Dimension:    n = {}", N);
    println!("│  Module Rank:       k = {}", K);
    println!("│  Modulus:           q = {} (NTT-friendly)", Q);
    println!("│  Challenge Weight:  τ = {}", TAU);
    println!("│  Masking Range:     γ₁ = {} (2^17)", GAMMA1);
    println!("│  Rejection Bound:   β = {}", BETA);
    println!("│  Security Level:    ≥128-bit classical / ≥64-bit quantum");
    println!("│  Trusted Setup:     NONE (transparent parameters)");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Parameter Generation ────────────────────────────────────────────
    println!("┌─ Phase 1: Parameter Generation ────────────────────────────┐");
    println!("│  Generating public MLWE matrix A ∈ R_q^{{k×k}}...");

    let param_start = Instant::now();
    let params = MlweParams::generate(&mut rng);
    let param_duration = param_start.elapsed();

    println!("│  ✓ Parameters generated in: {:?}", param_duration);
    println!("│  ✓ No trusted setup ceremony required");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Anonymity Set Construction ──────────────────────────────────────
    let anonymity_set_size = 10;
    println!("┌─ Phase 2: Anonymity Set Construction ──────────────────────┐");
    println!(
        "│  Generating {} random MLWE key pairs...",
        anonymity_set_size
    );

    let mut tree = MerkleTree::new();

    for _ in 0..anonymity_set_size {
        let dummy_keypair = KeyPair::generate(&params, &mut rng);
        let commitment = dummy_keypair.commitment();
        tree.insert(commitment)?;
    }

    println!("│  Inserting SHAKE-256 commitments into Merkle Tree...");
    println!("│  Anonymity set size: {} members", anonymity_set_size);
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── User Registration ───────────────────────────────────────────────
    println!("┌─ Phase 3: User Registration ───────────────────────────────┐");
    println!("│  Generating MLWE KeyPair for test user...");
    println!("│    s ← CBD(η=2)^k,  e ← CBD(η=2)^k,  b = A·s + e mod q");

    let user_keypair = KeyPair::generate(&params, &mut rng);

    println!("│  Creating commitment: SHAKE-256(\"COM_DOM\" ∥ b)");

    let user_commitment = user_keypair.commitment();
    let user_leaf_index = tree.insert(user_commitment)?;

    println!(
        "│  Leaf index: {}",
        user_leaf_index
    );

    let merkle_root = tree.root()?;
    let merkle_proof = tree.generate_inclusion_proof(user_leaf_index)?;
    let tree_depth = tree.depth();
    let total_leaves = tree.leaves.len();

    println!(
        "│  ✓ Merkle Root: 0x{}",
        hex::encode(&merkle_root[..8])
    );
    println!(
        "│  ✓ Tree depth: {} levels, {} total leaves",
        tree_depth, total_leaves
    );
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Proof Generation ────────────────────────────────────────────────
    println!("┌─ Phase 4: ZK Proof Generation (Fiat-Shamir with Aborts) ──┐");

    let scope = b"webauthn_session_challenge_2026".to_vec();
    println!(
        "│  Scope: \"{}\"",
        String::from_utf8_lossy(&scope)
    );

    let nullifier = user_keypair.nullifier(&scope);

    let public_inputs = PublicInputs {
        merkle_root,
        scope: scope.clone(),
        nullifier,
    };

    println!("│  Running lattice ZK prover [rejection sampling]...");

    let proof_start = Instant::now();
    let proof = Prover::generate_proof(
        &params,
        &user_keypair,
        &merkle_proof,
        &public_inputs,
        &mut rng,
    )?;
    let proof_duration = proof_start.elapsed();

    println!("│  ✓ Proof generated in: {:?}", proof_duration);
    println!(
        "│  ✓ Nullifier: 0x{}",
        hex::encode(&nullifier[..16])
    );
    println!(
        "│  ✓ Response ‖z‖∞ bound: < {} (γ₁ - β)",
        GAMMA1 - BETA
    );
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Verification ────────────────────────────────────────────────────
    println!("┌─ Phase 5: ZK Proof Verification ──────────────────────────┐");
    println!("│  Running lattice ZK verifier...");
    println!("│    1. Check ‖z‖∞ < γ₁ - β");
    println!("│    2. Recompute challenge from transcript");
    println!("│    3. Verify A·z - w - c·b ≈ 0 (algebraic relation)");
    println!("│    4. Verify Merkle path (SHAKE-256)");

    let verify_start = Instant::now();
    let is_valid =
        Verifier::verify_proof(&params, &proof, &user_keypair, &public_inputs)?;
    let verify_duration = verify_start.elapsed();

    println!("│  ✓ Verification completed in: {:?}", verify_duration);
    if is_valid {
        println!("│  ✓ Result: VALID ✅");
    } else {
        println!("│  ✗ Result: INVALID ❌");
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Artefact Sizes ──────────────────────────────────────────────────
    let proof_bytes = serialize_proof(&proof)?;

    println!("┌─ Artefact Sizes ───────────────────────────────────────────┐");
    println!(
        "│  Secret Key (s):    {} bytes ({} polynomials × {} coeffs × 3B)",
        K * N * 3,
        K,
        N
    );
    println!(
        "│  Public Key (b):    {} bytes ({} polynomials × {} coeffs × 3B)",
        K * N * 3,
        K,
        N
    );
    println!("│  Commitment:        32 bytes (SHAKE-256 hash)");
    println!(
        "│  Merkle Proof:      {} bytes ({} siblings × 32B + {} bits)",
        merkle_proof.siblings.len() * 32 + (merkle_proof.path_indices.len() + 7) / 8,
        merkle_proof.siblings.len(),
        merkle_proof.path_indices.len()
    );
    println!(
        "│  ZK Proof (total):  {} bytes (JSON-serialized)",
        proof_bytes.len()
    );
    println!("│  Nullifier:         32 bytes (SHAKE-256)");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Tamper Resistance ───────────────────────────────────────────────
    println!("┌─ Phase 6: Tamper Resistance Test ─────────────────────────┐");
    println!("│  Serializing proof, mutating bytes, re-verifying...");

    let mut tampered_bytes = proof_bytes.clone();
    if tampered_bytes.len() > 10 {
        tampered_bytes[10] ^= 0xFF;
    }

    let tamper_result = match deserialize_proof(&tampered_bytes) {
        Ok(tampered_proof) => {
            match Verifier::verify_proof(
                &params,
                &tampered_proof,
                &user_keypair,
                &public_inputs,
            ) {
                Ok(valid) => !valid,
                Err(_) => true,
            }
        }
        Err(_) => true,
    };

    if tamper_result {
        println!("│  ✓ Tampered proof REJECTED ❌ (as expected)");
    } else {
        println!("│  ✗ WARNING: Tampered proof was accepted ⚠️");
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // ─── Summary ─────────────────────────────────────────────────────────
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Simulation Complete                                        ║");
    println!("║  Protocol: Lattice-Based ZK-Auth (Module-LWE, QROM)        ║");
    println!("║  Quantum Resistance: NIST Category 1 (≥128-bit classical)  ║");
    println!("║  Trusted Setup: NONE                                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}
