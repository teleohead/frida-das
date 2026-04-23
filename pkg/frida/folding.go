// folding.go implements the FRI folding logic from Section 4.1 of the FRIDA paper.

package frida

import (
	"runtime"
	"sync"
)

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
func (SerialOrdinaryFolder) AlgebraicHash(prev, next, domain []Scalar, rho *Scalar, ff int) {
	prevSize := len(prev)
	nextSize := prevSize / ff
	preimageBuf := make([]int, ff)
	xs := make([]Scalar, ff)
	fs := make([]Scalar, ff)
	weights := make([]Scalar, ff)
	diffs := make([]Scalar, ff)

	for c := 0; c < nextSize; c++ {
		writePreimageIndices(c, prevSize, ff, preimageBuf)

		for k := 0; k < ff; k++ {
			idx := preimageBuf[k]
			xs[k] = domain[idx]
			fs[k] = prev[idx]
		}

		// Interpolate(rho, {(x_k, y_k): ...})
		next[c] = interpolateOrdinary(rho, xs[:ff], fs[:ff], weights, diffs)
	}
}

// AlgebraicHash implements FRI Algebraic Hash Function H_{rho_i}[G_{i-1}]
// This function is defined in Section 4.1 of the FRIDA Paper.
// Montgomery optimized. No parallelism.
func (SerialBatchFolder) AlgebraicHash(prev, next, domain []Scalar, rho *Scalar, ff int) {
	prevSize := len(prev)
	nextSize := prevSize / ff
	preimageBuf := make([]int, ff)
	xs := make([]Scalar, ff)
	fs := make([]Scalar, ff)
	weights := make([]Scalar, ff)
	diffs := make([]Scalar, ff)

	for c := 0; c < nextSize; c++ {
		writePreimageIndices(c, prevSize, ff, preimageBuf)

		for k := 0; k < ff; k++ {
			idx := preimageBuf[k]
			xs[k] = domain[idx]
			fs[k] = prev[idx]
		}

		// Interpolate(rho, {(x_k, y_k): ...})
		next[c] = interpolate(rho, xs[:ff], fs[:ff], weights, diffs)
	}
}

// AlgebraicHash implements FRI Algebraic Hash Function H_{rho_i}[G_{i-1}]
// This function is defined in Section 4.1 of the FRIDA Paper.
// Montgomery optimized. No parallelism.
func (ParallelBatchFolder) AlgebraicHash(prev, next, domain []Scalar, rho *Scalar, ff int) {
	prevSize := len(prev)
	nextSize := prevSize / ff

	numWorkers := runtime.NumCPU()
	if numWorkers > nextSize {
		numWorkers = nextSize
	}
	chunkSize := (nextSize + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > nextSize {
			end = nextSize
		}
		go func(start, end int) {
			defer wg.Done()

			preimageBuf := make([]int, ff)
			xs := make([]Scalar, ff)
			fs := make([]Scalar, ff)
			weights := make([]Scalar, ff)
			diffs := make([]Scalar, ff)

			for c := start; c < end; c++ {
				writePreimageIndices(c, prevSize, ff, preimageBuf)
				for k := 0; k < ff; k++ {
					idx := preimageBuf[k]
					xs[k] = domain[idx]
					fs[k] = prev[idx]
				}
				next[c] = interpolate(rho, xs[:ff], fs[:ff], weights, diffs)
			}
		}(start, end)
	}
	wg.Wait()
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
