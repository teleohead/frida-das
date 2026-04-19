package baseline

import "github.com/teleohead/frida-das/pkg/frida"

// Prover implements frida.ProverBackend.
type Prover struct {
	params frida.FriParams
}

func NewProver(params frida.FriParams) *Prover {
	return &Prover{params: params}
}

func (p *Prover) CommitAndProve(data []byte) (*frida.Commitment, *frida.ProverState, error) {
	return p.params.CommitAndProve(data)
}
