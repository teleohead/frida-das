// folding.go implements the FRI folding logic from Section 4.1 of the FRIDA paper.

package prover

import (
	"math/big"

	"github.com/teleohead/frida-das/pkg/frida"
)

// FoldAll runs the complete FRI folding phase.
func FoldAll(
	codeword []frida.Scalar,      // G_0
	foldingPool [][]frida.Scalar, // prelocated from Manager.FoldingPool
	challenges []frida.Scalar,    // rho_1, ..., rho_r
	domainSize int,               // |L_0|
	foldingFactor int,            // F
) [][]frida.Scalar {
	numRounds := len(challenges)

	preimageBuf := make([]int, foldingFactor)
	xs := make([]frida.Scalar, foldingFactor)
	fs := make([]frida.Scalar, foldingFactor)
	weights := make([]frida.Scalar, foldingFactor)
	diffs := make([]frida.Scalar, foldingFactor)

	currentDomain := GenerateDomain(domainSize)

	prev := codeword
	results := make([][]frida.Scalar, numRounds)

	for r := 0; r < numRounds; r++ {
		next := foldingPool[r]
		AlgebraicHash(prev, next, currentDomain, &challenges[r], foldingFactor, preimageBuf, xs, fs, weights, diffs)
		results[r] = next
		nextDomainSize := len(currentDomain) / foldingFactor
		if r < numRounds-1 {
			currentDomain = GenerateDomain(nextDomainSize)
		}
		prev = next
	}

	return results
}

// AlgebraicHash implements FRI Algebraic Hash Function H_{rho_i}[G_{i-1}]
// This function is defined in Section 4.1 of the FRIDA Paper.
func AlgebraicHash(
	prev []frida.Scalar,   // G_{i-1}
	next []frida.Scalar,   // G_i
	domain []frida.Scalar, // L_{i-1}
	rho *frida.Scalar,     // rho_i
	foldingFactor int,
	preimageBuf []int,
	xs []frida.Scalar,
	fs []frida.Scalar,
	weights []frida.Scalar,
	diffs []frida.Scalar,
) {
	prevSize := len(prev)
	nextSize := prevSize / foldingFactor

	for c := 0; c < nextSize; c++ {
		WritePreimageIndices(c, prevSize, foldingFactor, preimageBuf)

		for k := 0; k < foldingFactor; k++ {
			index := preimageBuf[k]
			xs[k] = domain[index]
			fs[k] = prev[index]
		}

		// Interpolate(rho, {(x_k, y_k): ...})
		next[c] = Interpolate(rho, xs[:foldingFactor], fs[:foldingFactor], weights, diffs)
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
	diffs []frida.Scalar,
) frida.Scalar {
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

	// reusable term [ w_j * f_j / (x - x_j) ] for summation
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

func GenerateDomain(domainSize int) []frida.Scalar {
	domain := make([]frida.Scalar, domainSize)

	// Goldilocks multiplicative generator: g = 7
	var g frida.Scalar
	g.SetUint64(7)

	// p - 1 = 2^64 - 2^32. We use bitwise operation for performance.
	pm1 := (uint64(0xFFFFFFFF) << 32) | uint64(0x00000000)
	// e = (p - 1) / n
	exp := pm1 / uint64(domainSize)

	// omega = g^e
	var omega frida.Scalar
	omega.Exp(g, new(big.Int).SetUint64(exp))

	// domain[0] = 1
	domain[0].SetOne()

	// domain[i] = omega * domain[i - 1]
	for i := 1; i < domainSize; i++ {
		domain[i].Mul(&domain[i-1], &omega)
	}

	return domain
}

// WritePreimageIndices writes the F preimage indices into the buf.
// For a coset index c in L_i, the F preimages are c + k*n/F, k = 0...(F-1)
func WritePreimageIndices(c, domainSize, foldingFactor int, buf []int) {
	stride := domainSize / foldingFactor
	for k := 0; k < foldingFactor; k++ {
		buf[k] = c + k*stride
	}
}
