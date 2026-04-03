// folding.go implements the FRI folding logic from Section 4.1 of the FRIDA paper.

package prover

import (
	"math/big"

	"github.com/teleohead/frida-das/pkg/frida"
)

func GenerateDomain(n int) []frida.Scalar {
	domain := make([]frida.Scalar, n)

	// Goldilocks multiplicative generator: g = 7
	var g frida.Scalar
	g.SetUint64(7)

	// p - 1 = 2^64 - 2^32. We use bitwise operation for performance.
	pm1 := (uint64(0xFFFFFFFF) << 32) | uint64(0x00000000)
	// e = (p - 1) / n
	exp := pm1 / uint64(n)

	// omega = g^e
	var omega frida.Scalar
	omega.Exp(g, new(big.Int).SetUint64(exp))

	// domain[0] = 1
	domain[0].SetOne()

	// domain[i] = omega * domain[i - 1]
	for i := 1; i < n; i++ {
		domain[i].Mul(&domain[i-1], &omega)
	}

	return domain
}

// MapCosetIndex maps an index in L_{i-1} to its coset representative in L_i under the map x -> x^F.
// This is just a helper function that computes the index.
func MapCosetIndex(i, domainSize, foldingFactor int) int {
	return i % (domainSize / foldingFactor)
}

// PreimageIndices writes the F preimage indices into the buf.
// For a coset index c in L_i, the F preimages are c + k*n/F, k = 0...(F-1)
func PreimageIndices(c, domainSize, foldingFactor int, buf []int) {
	stride := domainSize / foldingFactor
	for k := 0; k < foldingFactor; k++ {
		buf[k] = c + k*stride
	}
}

// Interpolate implements the Lagrange interpolation procedure.
// We use Barycentric Lagrange Interpolation. This is fast when F is small.
// weights and diffs are pre-allocated buffers to increase performance.
// See pp. 504, https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
func Interpolate(
	x *frida.Scalar,
	xs []frida.Scalar,
	fs []frida.Scalar,
	weights []frida.Scalar,
	diffs []frida.Scalar) frida.Scalar {
	n := len(xs)

	// w_j = 1 / PI_{k≠j} (x_j - x_k)
	for j := 0; j < n; j++ {
		weights[j].SetOne()
		for k := 0; k < n; k++ {
			if k == j {
				continue
			}
			var diff frida.Scalar
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
	var l frida.Scalar
	l.SetOne()
	for j := 0; j < n; j++ {
		l.Mul(&l, &diffs[j])
	}

	// sum = SUM_{j=0}^{n-1} [ w_j * f_j / (x - x_j) ]
	var sum frida.Scalar
	sum.SetZero()

	// reusable term [w_j * f_j / (x - x_j)] for summation
	var term frida.Scalar
	for j := 0; j < n; j++ {
		term.Mul(&weights[j], &fs[j])
		var invDiff frida.Scalar
		invDiff.Inverse(&diffs[j]) // we have confirmed diff_j != 0
		term.Mul(&term, &invDiff)
		sum.Add(&sum, &term)
	}

	// p(x) = l(x) * sum
	var result frida.Scalar
	result.Mul(&l, &sum)

	return result
}
