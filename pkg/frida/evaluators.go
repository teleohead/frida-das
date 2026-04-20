package frida

type PolyEvaluator interface {
	Evaluate(coeffs []Scalar, domain []Scalar) []Scalar
}

// BaselineEvaluator implements frida.PolyEvaluator using Horner's method.
type BaselineEvaluator struct{}

// Evaluate evaluates the polynomial defined by coeffs at each point in domain.
func (BaselineEvaluator) Evaluate(coeffs []Scalar, domain []Scalar) []Scalar {
	out := make([]Scalar, len(domain))
	rsEncodeHorner(coeffs, domain, out)
	return out
}

// BaselineEvaluator implements frida.PolyEvaluator using NTT (Number Theoretic Transforms).
type NTTEvaluator struct{} // TODO

// Evaluate evaluates the polynomial defined by coeffs at each point in domain.
func (NTTEvaluator) Evaluate(coeffs []Scalar, domain []Scalar) []Scalar {
	panic("TODO")
}
