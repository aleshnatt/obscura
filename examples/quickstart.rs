use rand::rngs::OsRng;

use obscura::error::ProtocolError;
use obscura::mlwe::MlweParams;
use obscura::protocol::{AuthenticatedRoot, KeyPair, Prover, PublicInputs, Verifier};
use obscura::tree::MerkleTree;

fn main() -> Result<(), ProtocolError> {
    let mut rng = OsRng;
    let params = MlweParams::generate(&mut rng);

    let mut tree = MerkleTree::new();
    let user = KeyPair::generate(&params, &mut rng);
    let user_index = tree.insert(user.commitment())?;
    let root = tree.root()?;
    let merkle_proof = tree.generate_inclusion_proof(user_index)?;

    let scope = b"session-challenge".to_vec();
    let authenticated_root = AuthenticatedRoot::from_trusted_source(root, &params);
    let public_inputs =
        PublicInputs::new_authenticated(authenticated_root, scope.clone(), user.nullifier(&scope));

    let proof = Prover::generate_proof(&params, &user, &merkle_proof, &public_inputs, &mut rng)?;

    assert!(Verifier::verify_proof(&params, &proof, &public_inputs)?);
    Ok(())
}
