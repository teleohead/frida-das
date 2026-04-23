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

// interpolateOrdinary implements the Lagrange interpolation procedure.
// We use Barycentric Lagrange Interpolation. This is fast when F is small.
// weights and diffs are pre-allocated buffers to increase performance.
// See pp. 504, https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
func interpolateOrdinary(
	x *Scalar,
	xs []Scalar,
	fs []Scalar,
	weights []Scalar,
	diffs []Scalar,
) Scalar {
	n := len(xs)

	// w_j = 1 / PI_{k≠j} (x_j - x_k)
	for j := 0; j < n; j++ {
		weights[j].SetOne()
		for k := 0; k < n; k++ {
			if k == j {
				continue
			}
			var diff Scalar
			diff.Sub(&xs[j], &xs[k])
			weights[j].Mul(&weights[j], &diff)
		}
		weights[j].Inverse(&weights[j])
	}

	// diffs_j = x - x_j
	for j := 0; j < n; j++ {
		diffs[j].Sub(x, &xs[j])
	}

	// edge case: If x happens to be one of the x-coordinates (x_j),
	// it means the challenge is exactly one of the points we have.
	// Simply return the value then.
	for j := 0; j < n; j++ {
		if diffs[j].IsZero() {
			return fs[j]
		}
	}

	// l(x) = PI_{j=0}^{n-1} (diffs_j)
	var l Scalar
	l.SetOne()
	for j := 0; j < n; j++ {
		l.Mul(&l, &diffs[j])
	}

	// sum = SUM_{j=0}^{n-1} [ w_j * f_j / (x - x_j) ]
	var sum Scalar
	sum.SetZero()

	// reusable term [ w_j * f_j / (x - x_j) ] for summation
	var term Scalar
	for j := 0; j < n; j++ {
		term.Mul(&weights[j], &fs[j])
		var invDiff Scalar
		invDiff.Inverse(&diffs[j]) // we have confirmed diff_j != 0
		term.Mul(&term, &invDiff)
		sum.Add(&sum, &term)
	}

	// p(x) = l(x) * sum
	var result Scalar
	result.Mul(&l, &sum)

	return result
}

// interpolate implements the Lagrange interpolation procedure with optimizations from Montgomery's batch inversion.
// We use Barycentric Lagrange Interpolation. This is fast when F is small.
// weights and diffs are pre-allocated buffers to increase performance.
// See pp. 504, https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
func interpolate(
	x *Scalar,
	xs []Scalar,
	fs []Scalar,
	weights []Scalar,
	diffs []Scalar,
) Scalar {
	n := len(xs)
	for j := 0; j < n; j++ {
		diffs[j].Sub(x, &xs[j])
	}

	for j := 0; j < n; j++ {
		if diffs[j].IsZero() {
			return fs[j]
		}
	}

	var l Scalar
	l.SetOne()
	for j := 0; j < n; j++ {
		l.Mul(&l, &diffs[j])
	}

	for j := 0; j < n; j++ {
		weights[j].SetOne()
		for k := 0; k < n; k++ {
			if k == j {
				continue
			}
			var d Scalar
			d.Sub(&xs[j], &xs[k])
			weights[j].Mul(&weights[j], &d)
		}
	}

	// Batch-invert weights and diffs
	inPlaceBatchInverse(weights[:n])
	inPlaceBatchInverse(diffs[:n])

	var sum Scalar
	sum.SetZero()
	var term Scalar
	for j := 0; j < n; j++ {
		term.Mul(&weights[j], &fs[j])
		term.Mul(&term, &diffs[j])
		sum.Add(&sum, &term)
	}

	var result Scalar
	result.Mul(&l, &sum)

	return result
}

// inPlaceBatchInverse implements Montgomery's batch inversion strategy.
// see: https://medium.com/eryxcoop/montgomerys-trick-for-batch-galois-field-inversion-9b6d0f399da2
func inPlaceBatchInverse(vec []Scalar) {
	len := len(vec)
	if len == 0 {
		return
	}
	if len == 1 {
		vec[0].Inverse(&vec[0])
		return
	}

	betas := make([]Scalar, len)
	betas[0] = vec[0]
	for i := 1; i < len; i++ {
		betas[i].Mul(&betas[i-1], &vec[i])
	}

	var inv Scalar
	inv.Inverse(&betas[len-1])

	for i := len - 1; i > 0; i-- {
		var elem Scalar
		elem.Mul(&inv, &betas[i-1])
		inv.Mul(&inv, &vec[i])
		vec[i] = elem
	}

	vec[0] = inv
}
