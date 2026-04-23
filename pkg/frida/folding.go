// folding.go implements the FRI folding logic from Section 4.1 of the FRIDA paper.

package frida

import (
	"runtime"
	"sync"
)

// Folder controls how AlgebraicHash (FRI folding) is computed
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
		next[c] = interpolateMontgomery(rho, xs[:ff], fs[:ff], weights, diffs)
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
				next[c] = interpolateMontgomery(rho, xs[:ff], fs[:ff], weights, diffs)
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

// interpolateMontgomery implements the Lagrange interpolation procedure with optimizations from Montgomery's batch inversion.
// We use Barycentric Lagrange Interpolation. This is fast when F is small.
// weights and diffs are pre-allocated buffers to increase performance.
// See pp. 504, https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
func interpolateMontgomery(
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
