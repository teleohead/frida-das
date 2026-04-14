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

// Interpolate implements the Lagrange interpolation procedure.
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

// BatchCombine computes G_0 = SUM_{j=0}^{B-1} xi^j * G_j for batched FRI.
func batchCombine(
	interleavedBatch []Scalar, // is in interleaved layout (B * domainSize elements)
	xi *Scalar, // batching challenge xi
	batchSize int,
	domainSize int,
	out []Scalar, // is the combined codeword G_0, len = domainSize
) {
	lastJ := batchSize - 1
	for s := 0; s < domainSize; s++ {
		// start with the highest polynomial value for this point
		out[s] = interleavedBatch[s*batchSize+lastJ]
		// use Horner's to fold in the rest of the polynomials for this point
		for j := lastJ - 1; j >= 0; j-- {
			out[s].Mul(&out[s], xi)
			out[s].Add(&out[s], &interleavedBatch[s*batchSize+j])
		}
	}
}

// RSEncodeBatch encodes B polynomials, see in Section 4.3 of the paper.
// It produces the interleaved codeword.
// This matches the storage.InterleavedSlab layout.
func rsEncodeBatch(
	polys [][]Scalar,
	domain []Scalar, // L_0
	out []Scalar, // must be pre-allocated with len = len(polys) * len(domain), interleaved!
) {
	batchSize := len(polys)   // B
	domainSize := len(domain) // |L_0|
	buf := make([]Scalar, domainSize)
	for j := 0; j < batchSize; j++ {
		rsEncode(polys[j], domain, buf)
		for idx := 0; idx < domainSize; idx++ {
			out[idx*batchSize+j] = buf[idx]
		}
	}
}

// RSEncode implements Reed-Solomon Encoding.
// We use Horner's Method f(x) = c_0 + x(c_1 + x(c_2 + ...)) to reduce the number of operations.
func rsEncode(
	poly []Scalar, // a polynomial represented by an array of its coefficients
	domain []Scalar,
	out []Scalar, // must be pre-allocated with len = len(domain)
) {
	if len(poly) == 0 {
		return
	}
	deg := len(poly) - 1
	for i, x := range domain {
		out[i] = poly[deg]
		// f(x) = c_0 + x(c_1 + x(c_2 + ...))
		for j := deg - 1; j >= 0; j-- {
			out[i].Mul(&out[i], &x)
			out[i].Add(&out[i], &poly[j])
		}
	}
}
