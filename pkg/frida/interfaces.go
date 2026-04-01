package frida

// FridaBuilder build provers with given parameters.
type FridaBuilder struct {
	Params FriParams
}

// NewBuilder creates a builder with the given parameters
func NewBuilder(p FriParams) *FridaBuilder {
	return &FridaBuilder{Params: p}
}

// CommitAndProve encodes data, FRI-commit, and returns the Commitment and a FridaProver for opening.
func (b *FridaBuilder) CommitAndProve(data []byte) (*Commitment, *FridaProver, error) {
	return nil, nil, nil
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

// Open generates an FriProof for given positions.
func (p *FridaProver) Open(positions []int) (*FriProof, error) {
	return nil, nil
}

type FridaVerifier struct {
	Params     FriParams
	commitment *Commitment
	// challenges are recomputed from Commitment.Roots
	challenges []Scalar
	domainSize int
}

// Verify checks an FriProof for given evaluations and positions.
func (v *FridaVerifier) Verify(proof *FriProof, evaluations []Scalar, positions []int) error {
	return nil
}
