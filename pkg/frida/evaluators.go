package frida

type PolyEvaluator interface {
  // Evaluate evaluates the polynomial defined by coeffs at each point in domain
	Evaluate(coeffs []Scalar, domain []Scalar) []Scalar
}

// BaselineEvaluator implements frida.PolyEvaluator using Horner's method.
type BaselineEvaluator struct{}

func (BaselineEvaluator) Evaluate(coeffs []Scalar, domain []Scalar) []Scalar {
	out := make([]Scalar, len(domain))
	rsEncodeHorner(coeffs, domain, out)
	return out
}

// BaselineEvaluator implements frida.PolyEvaluator using NTT (Number Theoretic Transforms).
type NTTEvaluator struct{} // TODO

func (NTTEvaluator) Evaluate(coeffs []Scalar, domain []Scalar) []Scalar {
	out := make([]Scalar, len(domain))
	copy(out, coeffs)
	omega := domain[1]
	return ntt(out, omega)
}
