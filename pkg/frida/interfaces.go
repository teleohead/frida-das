package frida

// FridaBuilder build provers with given parameters.
type FridaBuilder interface {
	// CommitAndProve encodes data, FRI-commit, and returns the Commitment and a FridaProver for opening.
	CommitAndProve(data []byte) (*Commitment, *FridaProver, error)
}

type FridaProver struct {
	Params     FriParams
	domainSize int

	// B interleaved codewords (nil if B = 1)
	batchOracle []Scalar
	// G_0
	codeword []Scalar
	// G_1, G_2, ..., G_r
	foldedOracles [][]Scalar
	// rho_1, rho_2, ... rho_r
	challenges []Scalar
	// xi
	batchChallenge Scalar
	// Merkle Trees
	trees []MerkleTree
}

type Prover interface {
	// Open generates an FriProof for given positions.
	Open(positions []int) (*FriProof, error)
}

type FridaVerifier struct {
	Params     FriParams
	commitment *Commitment
	// challenges are recomputed from Commitment.Roots
	challenges []Scalar
	domainSize int
}

// Verifier defines the core logic for the FRI verification process.
type Verifier interface {
	// Verify checks an FriProof for given evaluations and positions.
	Verify(proof *FriProof, evaluations []Scalar, positions []int) error
}
