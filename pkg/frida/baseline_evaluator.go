package frida

// BaselineEvaluator implements frida.PolyEvaluator using Horner's method.
type BaselineEvaluator struct{}

// Evaluate evaluates the polynomial defined by coeffs at each point in domain.
func (BaselineEvaluator) Evaluate(coeffs []Scalar, domain []Scalar) []Scalar {
	out := make([]Scalar, len(domain))
	rsEncode(coeffs, domain, out)
	return out
}
