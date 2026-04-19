package baseline

import "github.com/teleohead/frida-das/pkg/frida"

// Prover implements frida.ProverBackend.
type Prover struct {
	params frida.FriParams
	eval   frida.PolyEvaluator
}

func NewProver(params frida.FriParams, eval frida.PolyEvaluator) *Prover {
	return &Prover{params: params, eval: eval}
}

func (p *Prover) CommitAndProve(data []byte) (*frida.Commitment, *frida.ProverState, error) {
	return frida.CommitAndProveWith(p.params, data, p.eval)
}
