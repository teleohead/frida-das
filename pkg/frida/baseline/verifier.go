package baseline

import "github.com/teleohead/frida-das/pkg/frida"

// Verifier implements frida.VerifierBackend.
type Verifier struct {
	v *frida.Verifier
}

func NewVerifier(params frida.FriParams, commitment *frida.Commitment) (*Verifier, error) {
	v, err := frida.NewVerifier(params, commitment)
	if err != nil {
		return nil, err
	}
	return &Verifier{v: v}, nil
}

func (bv *Verifier) Verify() error {
	return bv.v.Verify()
}

func (bv *Verifier) VerifySample(pos int, proof *frida.FriProof, evals []frida.Scalar) error {
	return bv.v.VerifySample(pos, proof, evals)
}
