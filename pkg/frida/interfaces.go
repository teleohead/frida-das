package frida

// FridaBuilder build provers with given parameters.
type FridaBuilder interface {
	// CommitAndProve encodes data, FRI-commit, and returns the Commitment and a FridaProver for opening.
	CommitAndProve(data []byte) (*Commitment, *FridaProver, error)
}

type FridaProver struct {
	Params     FriParams
	DomainSize int

	// B interleaved codewords (nil if B = 1)
	BatchOracle []Scalar
	// G_0
	Codeword []Scalar
	// G_1, G_2, ..., G_r
	FoldedOracles [][]Scalar
	// rho_1, rho_2, ... rho_r
	Challenges []Scalar
	// xi
	BatchChallenge Scalar
	// Merkle Trees
	Trees []MerkleTree
}

type Prover interface {
	// Open generates an FriProof for given positions.
	Open(positions []int) (*FriProof, error)
}

type FridaVerifier struct {
	Params     FriParams
	Commitment *Commitment
	// challenges are recomputed from Commitment.Roots
	Challenges []Scalar
	DomainSize int
}

// Verifier defines the core logic for the FRI verification process.
type Verifier interface {
	// Verify checks an FriProof for given evaluations and positions.
	Verify(proof *FriProof, evaluations []Scalar, positions []int) error
}
