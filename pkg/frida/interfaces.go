package frida

type PolyEvaluator interface {
	Evaluate(coeffs []Scalar, domain []Scalar) []Scalar
}

type ProverBackend interface {
	CommitAndProve(data []byte) (*Commitment, *ProverState, error)
}

type VerifierBackend interface {
	Verify() error
	VerifySample(pos int, proof *FriProof, evals []Scalar) error
}
