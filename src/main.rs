//! # Obscura Protocol — CLI Testbed & Benchmark
//!
//! Full end-to-end protocol simulation with Groth16 proofs.

use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;

use obscura::poseidon::poseidon_config;
use obscura::protocol::{
    deserialize_proof, serialize_proof, trusted_setup, KeyPair, Prover, PublicInputs, Verifier,
};
use obscura::tree::MerkleTree;

/// Obscura Protocol — Anonymous WebAuthn Credential Engine (Groth16/BN254)
#[derive(Parser)]
#[command(name = "obscura")]
#[command(about = "ZK-augmented FIDO2/WebAuthn protocol simulator with Groth16 proofs")]
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

/// Convert a BN254 field element to a hex string.
fn fr_to_hex(f: &Fr) -> String {
    let bigint = (*f).into_bigint();
    let bytes = bigint.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
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
    let config = poseidon_config();

    println!("ZK-FIDO2 Simulator");

    println!("Trusted Setup");
    println!("Running Groth16 circuit-specific setup...");
    println!("Generating CRS (proving key + verification key)");

    let setup_start = Instant::now();
    let anonymity_set_size = 10;

    // For 11 leaves (10 + 1 user), padded to 16 → depth = 4.
    let estimated_depth = ((anonymity_set_size + 1) as f64)
        .log2()
        .ceil() as usize;
    let params = trusted_setup(estimated_depth, &mut rng)?;
    let setup_duration = setup_start.elapsed();

    // Measure key sizes
    let mut pk_bytes = Vec::new();
    params
        .proving_key
        .serialize_compressed(&mut pk_bytes)
        .unwrap();
    let mut vk_bytes = Vec::new();
    params
        .verifying_key
        .serialize_compressed(&mut vk_bytes)
        .unwrap();

    println!("  \u{2713} Trusted setup completed in: {:?}", setup_duration);
    println!("  \u{2713} Proving key size: {} bytes", pk_bytes.len());
    println!(
        "  \u{2713} Verification key size: {} bytes",
        vk_bytes.len()
    );
    println!();

    println!("Setup");
    println!(
        "Generating anonymity set ({} random commitments)",
        anonymity_set_size
    );

    let mut tree = MerkleTree::with_config(config.clone());

    for _ in 0..anonymity_set_size {
        let dummy_keypair = KeyPair::generate(&mut rng);
        let commitment = dummy_keypair.commitment(&config);
        tree.insert(commitment)?;
    }

    println!("Inserting Poseidon commitments into Merkle Tree...");
    println!(
        "Anonymity set size: {} members",
        anonymity_set_size
    );
    println!();

    println!("Registration");
    println!("Generating KeyPair for test user");

    let user_keypair = KeyPair::generate(&mut rng);

    println!("Creating commitment: Poseidon(sk, nonce)");

    let user_commitment = user_keypair.commitment(&config);

    println!("  Inserting user commitment into Merkle Tree...");

    let user_leaf_index = tree.insert(user_commitment)?;

    println!(
        "  Generating inclusion proof for leaf index: {}",
        user_leaf_index
    );

    let merkle_root = tree.root()?;
    let merkle_proof = tree.generate_inclusion_proof(user_leaf_index)?;
    let tree_depth = tree.depth();
    let total_leaves = tree.leaves.len();

    println!(
        "  \u{2713} Final Merkle Root: {}",
        fr_to_hex(&merkle_root)
    );
    println!(
        "  \u{2713} Tree depth: {} levels, {} total leaves",
        tree_depth, total_leaves
    );
    println!();

    println!("Proof Generation");

    // Generate server challenge.
    let challenge = Fr::rand(&mut rng);
    println!("Issuing server challenge: {}", fr_to_hex(&challenge));

    // Derive nullifier.
    let nullifier = user_keypair.nullifier(&config, &challenge);

    let public_inputs = PublicInputs {
        merkle_root,
        challenge,
        nullifier,
    };

    println!("  Running Groth16::prove() [elliptic curve math]...");
    let proof_start = Instant::now();
    let groth16_proof = Prover::generate_proof(
        &user_keypair,
        &merkle_proof,
        &public_inputs,
        &params.proving_key,
        &mut rng,
    )?;
    let proof_duration = proof_start.elapsed();

    println!("  \u{2713} Proof generated in: {:?}", proof_duration);
    println!("  \u{2713} Nullifier: {}", fr_to_hex(&nullifier));
    println!();

    println!("Verification");
    println!("Running Groth16::verify() [3 bilinear pairings on BN254]");

    let verify_start = Instant::now();
    let is_valid =
        Verifier::verify_proof(&groth16_proof, &public_inputs, &params.verifying_key)?;
    let verify_duration = verify_start.elapsed();

    println!("  \u{2713} Verification completed in: {:?}", verify_duration);
    if is_valid {
        println!("  \u{2713} Result: Valid \u{2705}");
    } else {
        println!("  \u{2717} Result: Invalid \u{274C}");
    }
    println!();

    println!("Artefact Sizes");

    let proof_bytes = serialize_proof(&groth16_proof)?;

    println!("Secret Key     : 32 bytes (BN254 scalar)");
    println!("Nonce          : 32 bytes (BN254 scalar)");
    println!("Commitment     : 32 bytes (Poseidon hash)");
    println!(
        "Merkle Proof   : {} bytes ({} siblings \u{00D7} 32 + {} bits)",
        merkle_proof.siblings.len() * 32 + (merkle_proof.path_indices.len() + 7) / 8,
        merkle_proof.siblings.len(),
        merkle_proof.path_indices.len()
    );
    println!(
        "  Groth16 Proof  : {} bytes (compressed: A \u{2208} G\u{2081}, B \u{2208} G\u{2082}, C \u{2208} G\u{2081})",
        proof_bytes.len()
    );
    println!("Public Inputs  : 64 bytes (root + nullifier)");
    println!();

    println!("Tamper Resistance Test");
    println!("Serializing proof, mutating bytes, re-verifying...");

    let mut tampered_bytes = proof_bytes.clone();
    // Flip a bit in the proof.
    if tampered_bytes.len() > 4 {
        tampered_bytes[4] ^= 0xFF;
    }

    let tamper_result = match deserialize_proof(&tampered_bytes) {
        Ok(tampered_proof) => {
            match Verifier::verify_proof(
                &tampered_proof,
                &public_inputs,
                &params.verifying_key,
            ) {
                Ok(valid) => !valid,
                Err(_) => true, // Error during verification = rejected
            }
        }
        Err(_) => true, // Deserialization failure = rejected
    };

    if tamper_result {
        println!("  \u{2713} Tampered proof rejected: Invalid \u{274C}");
    } else {
        println!("  \u{2717} Tampered proof accepted: Valid \u{2705}");
    }
    println!();

    println!("Simulation Complete");
    println!("Groth16/BN254");
    println!();

    Ok(())
}
