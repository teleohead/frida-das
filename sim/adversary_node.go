package sim

import "github.com/teleohead/frida-das/pkg/frida"

// AdversaryNode is a malicious block proposer. It serves corrupted data.
// This is used to test if honest LightNode's reject bad proofs.
type AdversaryNode struct {
	// CorruptPosition records the positions where AdversaryNode returns garbage data.
	CorruptPositions map[int]bool
}

// NewAdversaryNode creates an adversary node that corrupts data at given positions.
func NewAdversaryNode(positions []int) *AdversaryNode {
	m := make(map[int]bool, len(positions))
	for _, p := range positions {
		m[p] = true
	}
	return &AdversaryNode{CorruptPositions: m}
}

// IsCorrupt returns if the adversary corrupts the given pos.
func (adv *AdversaryNode) IsCorrupt(pos int) bool {
	return adv.CorruptPositions[pos]
}

// CreateCorruptResponse creates a corrupt response for a corrupted position
func (adv *AdversaryNode) CreateCorruptResponse(pos int, batchSize int) SampleResponse {
	evals := make([]frida.Scalar, batchSize)
	for i := range evals {
		evals[i].SetUint64(uint64(0x8BADF00D) + 1)
	}
	return SampleResponse{
		Position:    pos,
		Evaluations: evals,
		Proof:       frida.FriProof{}, // empty proof
		Err:         nil,
	}
}
