package sim

import (
	"github.com/teleohead/frida-das/internal/prover"
	"github.com/teleohead/frida-das/pkg/frida"
)

// DataProvider generates a SampleResponse for a given position.
// It is utilized by the Network.
type DataProvider interface {
	ProvideResponse(p *frida.FridaProver, pos int) SampleResponse
}

// HonestProvider produces real opening proofs and evaluations.
type HonestProvider struct{}

// NewHonestProvider creates an honest node that corrupts nothing and provide an honest response.
func NewHonestProvider() *HonestProvider {
	return &HonestProvider{}
}

func (hp *HonestProvider) ProvideResponse(p *frida.FridaProver, pos int) SampleResponse {
	proof, err := prover.Open(p, []int{pos})

	if err != nil {
		return SampleResponse{Position: pos, Err: err}
	}

	evals := extractEvaluations(p, pos)

	return SampleResponse{
		Position:    pos,
		Evaluations: evals,
		Proof:       *proof,
	}
}

// MaliciousProvider is a malicious block proposer. It serves corrupted data.
// This is used to test if honest LightNode's reject bad proofs.
type MaliciousProvider struct {
	// CorruptPosition records the positions where AdversaryNode returns garbage data.
	CorruptPositions map[int]bool
	hp               *HonestProvider
}

// NewMaliciousProvider creates an adversary node that corrupts data at given positions.
func NewMaliciousProvider(positions []int) *MaliciousProvider {
	m := make(map[int]bool, len(positions))
	for _, p := range positions {
		m[p] = true
	}
	return &MaliciousProvider{
		CorruptPositions: m,
		hp:               NewHonestProvider(),
	}
}

// ProvideResponse creates a corrupt response for a corrupted position
func (mp *MaliciousProvider) ProvideResponse(p *frida.FridaProver, pos int) SampleResponse {
	if !mp.CorruptPositions[pos] {
		return mp.hp.ProvideResponse(p, pos)
	}
	evals := make([]frida.Scalar, p.Params.BatchSize)
	for i := range evals {
		evals[i].SetUint64(uint64(0x8BADF00D + i))
	}
	return SampleResponse{
		Position:    pos,
		Evaluations: evals,
		Proof:       frida.FriProof{}, // empty proof
		Err:         nil,
	}
}

// extractEvaluations reads the B interleaved elements at domain point s (pos) from the prover's batchOracle.
func extractEvaluations(p *frida.FridaProver, pos int) []frida.Scalar {
	B := p.Params.BatchSize
	evals := make([]frida.Scalar, B)
	if p.BatchOracle != nil {
		base := pos * B
		copy(evals, p.BatchOracle[base:base+B])
	} else {
		evals[0] = p.Codeword[pos]
	}
	return evals
}
