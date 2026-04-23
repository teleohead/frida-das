// folding.go implements the FRI folding logic from Section 4.1 of the FRIDA paper.

package frida

// Folder controls how algebraicHash (FRI folding) is computed
type Folder interface {
	AlgebraicHash(prev, next, domain []Scalar, rho *Scalar, foldingFactor int)
}

// SerialOrdinaryFolder folds cosets serially using per-element field inversion
type SerialOrdinaryFolder struct{}

// SerialBatchFolder folds cosets serially using Montgomery batch inversion
type SerialBatchFolder struct{}

// ParallelBatchFolder folds cosets in parallel using Montgomery batch inversion
type ParallelBatchFolder struct{}

// AlgebraicHash implements FRI Algebraic Hash Function H_{rho_i}[G_{i-1}]
// This function is defined in Section 4.1 of the FRIDA Paper.
// No Montgomery optimization. No parallelism.
func (SerialOrdinaryFolder) AlgebraicHash(
	prev []Scalar,   // G_{i-1}
	next []Scalar,   // G_i
	domain []Scalar, // L_{i-1}
	rho *Scalar,     // rho_i
	foldingFactor int,
	preimageBuf []int,
	xs []Scalar,
	fs []Scalar,
	weights []Scalar,
	diffs []Scalar,
) {
	prevSize := len(prev)
	nextSize := prevSize / foldingFactor

	for c := 0; c < nextSize; c++ {
		writePreimageIndices(c, prevSize, foldingFactor, preimageBuf)

		for k := 0; k < foldingFactor; k++ {
			index := preimageBuf[k]
			xs[k] = domain[index]
			fs[k] = prev[index]
		}

		// Interpolate(rho, {(x_k, y_k): ...})
		next[c] = interpolateOrdinary(rho, xs[:foldingFactor], fs[:foldingFactor], weights, diffs)
	}
}

// AlgebraicHash implements FRI Algebraic Hash Function H_{rho_i}[G_{i-1}]
// This function is defined in Section 4.1 of the FRIDA Paper.
// Montgomery optimized. No parallelism.
func (SerialBatchFolder) AlgebraicHash(
	prev []Scalar,   // G_{i-1}
	next []Scalar,   // G_i
	domain []Scalar, // L_{i-1}
	rho *Scalar,     // rho_i
	foldingFactor int,
	preimageBuf []int,
	xs []Scalar,
	fs []Scalar,
	weights []Scalar,
	diffs []Scalar,
) {
	prevSize := len(prev)
	nextSize := prevSize / foldingFactor

	for c := 0; c < nextSize; c++ {
		writePreimageIndices(c, prevSize, foldingFactor, preimageBuf)

		for k := 0; k < foldingFactor; k++ {
			index := preimageBuf[k]
			xs[k] = domain[index]
			fs[k] = prev[index]
		}

		// Interpolate(rho, {(x_k, y_k): ...})
		next[c] = interpolateOrdinary(rho, xs[:foldingFactor], fs[:foldingFactor], weights, diffs)
	}
}

// writePreimageIndices writes the F preimage indices into the buf.
// For a coset index c in L_i, the F preimages are c + k*n/F, k = 0...(F-1)
func writePreimageIndices(c, domainSize, foldingFactor int, buf []int) {
	stride := domainSize / foldingFactor
	for k := 0; k < foldingFactor; k++ {
		buf[k] = c + k*stride
	}
}

// computeNumRounds calculates the number of FRI folding rounds.
// numCoeffs is the number of coefficients of a polynomial. e.g. x^2 + x + 1 has degree of 3.
func computeNumRounds(numCoeffs, foldingFactor, maxRemainderDegree int) int {
	r := 0
	n := numCoeffs
	for n > maxRemainderDegree+1 {
		n /= foldingFactor
		r++
	}
	return r
}
