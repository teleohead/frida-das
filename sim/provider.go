package sim

import (
	"github.com/teleohead/frida-das/internal/prover"
	"github.com/teleohead/frida-das/pkg/frida"
)

type Provider interface {
	ProvideResponse(p *frida.FridaProver, pos int) SampleResponse
}

// HonestProvider produces real opening proofs and evaluations.
type HonestProvider struct{}

func NewHonestProvider() *HonestProvider {
	return &HonestProvider{}
}

func (hp *HonestProvider) ProvideResponse(p *frida.FridaProver, pos int) SampleResponse {
	proof, err := prover.Open(p, []int{pos})

	if err != nil {
		return SampleResponse{Position: pos, Err: err}
	}

	evals := extractEvaluations(state, pos)

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
	hp               HonestProvider
}

// NewMaliciousProvider creates an adversary node that corrupts data at given positions.
func NewMaliciousProvider(positions []int) *MaliciousProvider {
	m := make(map[int]bool, len(positions))
	for _, p := range positions {
		m[p] = true
	}
	return &MaliciousProvider{CorruptPositions: m}
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
