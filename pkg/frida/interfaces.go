package frida

// FridaBuilder build provers with given parameters.
type FridaBuilder interface {
	// CommitAndProve encodes data, FRI-commit, and returns the Commitment and a FridaProver for opening.
	CommitAndProve(data []byte) (*Commitment, *FridaProver, error)
}

type Prover interface {
	// Open generates an FriProof for given positions.
	Open(positions []int) (*FriProof, error)
}

// Verifier defines the core logic for the FRI verification process.
type Verifier interface {
	// Verify checks an FriProof for given evaluations and positions.
	Verify(proof *FriProof, evaluations []Scalar, positions []int) error
}
