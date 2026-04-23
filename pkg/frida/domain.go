package frida

import (
	"math/big"
)

func generateDomain(domainSize int) []Scalar {
	domain := make([]Scalar, domainSize)

	// Goldilocks multiplicative generator: g = 7
	var g Scalar
	g.SetUint64(7)

	// p - 1 = 2^64 - 2^32
	pm1 := uint64(GoldilocksPrime - 1)
	// e = (p - 1) / n
	exp := pm1 / uint64(domainSize)

	// omega = g^e
	var omega Scalar
	omega.Exp(g, new(big.Int).SetUint64(exp))

	// domain[0] = 1
	domain[0].SetOne()

	// domain[i] = omega * domain[i - 1]
	for i := 1; i < domainSize; i++ {
		domain[i].Mul(&domain[i-1], &omega)
	}

	return domain
}

// primitiveRoot returns ω, the primitive n-th root of unity in the Goldilocks field for a given domain size
// It is used by Verifier to check folding consistency.
func primitiveRoot(domainSize int) Scalar {
	var g Scalar
	g.SetUint64(7)

	pm1 := uint64(GoldilocksPrime - 1)
	exp := pm1 / uint64(domainSize)

	var omega Scalar
	omega.Exp(g, new(big.Int).SetUint64(exp))
	return omega
}
