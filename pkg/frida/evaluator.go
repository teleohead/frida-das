package frida

type PolyEvaluator interface {
	Evaluate(coeffs []Scalar, domain []Scalar) []Scalar
}
