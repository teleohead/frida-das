package frida

type ErasureCodeCommitment interface {
	Com(data []Scalar) (Commitment, State, error)

	Open(state State, index int) (Proof, error)

	Ver(com Commitment, index int, symbol []Scalar, proof Proof) bool
}
