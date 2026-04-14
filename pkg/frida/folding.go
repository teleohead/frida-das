// folding.go implements the FRI folding logic from Section 4.1 of the FRIDA paper.

package frida

// algebraicHash implements FRI Algebraic Hash Function H_{rho_i}[G_{i-1}]
// This function is defined in Section 4.1 of the FRIDA Paper.
func algebraicHash(
	prev []Scalar, // G_{i-1}
	next []Scalar, // G_i
	domain []Scalar, // L_{i-1}
	rho *Scalar, // rho_i
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
		next[c] = Interpolate(rho, xs[:foldingFactor], fs[:foldingFactor], weights, diffs)
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
// degree is the number of coefficients of a polynomial. e.g. x^2 + x + 1 has degree of 3.
func computeNumRounds(degree, foldingFactor, maxRemainderDegree int) int {
	r := 0
	d := degree
	for d > maxRemainderDegree+1 {
		d /= foldingFactor
		r++
	}
	return r
}
