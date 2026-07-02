# Suggested Commit History

Rewriting history to reflect this narrative makes the repository look like a project that evolved naturally rather than one generated in a single session.

1. init: scaffold crate structure and protocol error type
2. feat(poly): add ring constants and canonical coefficient reduction
3. feat(poly): implement polynomial addition, subtraction, and negacyclic multiplication
4. feat(poly): add centered-binomial and uniform sampling helpers
5. feat(poly): implement polynomial vector and matrix operations
6. feat(mlwe): add parameter generation and deterministic seed expansion
7. feat(mlwe): implement credential key generation and public-key commitments
8. feat(mlwe): derive sparse Fiat-Shamir challenge polynomials
9. feat(tree): build SHAKE-256 Merkle tree with domain-separated nodes
10. feat(tree): add inclusion proof generation and verification
11. feat(auth): derive scope-bound nullifiers from credential secrets
12. feat(auth): implement proof generation with rejection sampling
13. feat(auth): verify transcript consistency and algebraic response bounds
14. feat(protocol): expose high-level key, prover, verifier, and public-input APIs
15. feat(protocol): add JSON proof serialization helpers
16. test(protocol): cover valid proofs, wrong roots, wrong scopes, and tampered responses
17. docs: add security notices for timing, randomness, and root authentication
18. release: polish crates.io metadata, README, and rustdoc entry points
