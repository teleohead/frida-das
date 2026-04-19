package baseline

import "github.com/teleohead/frida-das/pkg/frida"

// Evaluator implements frida.PolyEvaluator using Horner's method.
type Evaluator struct{}

// Evaluate evaluates the polynomial defined by coeffs at each point in domain.
func (Evaluator) Evaluate(coeffs []frida.Scalar, domain []frida.Scalar) []frida.Scalar {
	out := make([]frida.Scalar, len(domain))
	frida.RSEncode(coeffs, domain, out)
	return out
}
