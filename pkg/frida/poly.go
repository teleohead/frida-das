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

// iFFT computes the Inverse Fast Fourier Transform of the given evaluations.
// The length of evals must be a power of 2.
// omegaInv is the inverse primitive root of unity for the domainSize.
func iFFT(evals []Scalar, omegaInv Scalar) []Scalar {
	n := len(evals)
	if n == 0 {
		return nil
	}

	// 1. Bit-reversal permutation (in-place copy)
	coeffs := make([]Scalar, n)
	shift := 32 - bitLen(uint32(n-1))
	for i := 0; i < n; i++ {
		rev := reverseBits(uint32(i)) >> shift
		coeffs[rev] = evals[i]
	}

	// 2. Cooley-Tukey iterative iFFT
	for length := 2; length <= n; length *= 2 {
		half := length / 2

		// omegaStep = omegaInv ^ (n / length)
		var omegaStep Scalar
		exp := uint64(n / length)
		omegaStep.Exp(omegaInv, new(big.Int).SetUint64(exp))

		for i := 0; i < n; i += length {
			var w Scalar
			w.SetOne()
			for j := 0; j < half; j++ {
				u := coeffs[i+j]
				var v, tmp Scalar
				// v = w * coeffs[i+j+half]
				tmp = coeffs[i+j+half]
				v.Mul(&tmp, &w)
				// coeffs[i+j] = u + v
				coeffs[i+j].Add(&u, &v)
				// coeffs[i+j+half] = u - v
				coeffs[i+j+half].Sub(&u, &v)
				// w = w * omegaStep
				tmp = w
				w.Mul(&tmp, &omegaStep)
			}
		}
	}

	// 3. Multiply by modular inverse of N
	var nScalar, nInv Scalar
	nScalar.SetUint64(uint64(n))
	nInv.Inverse(&nScalar)

	for i := 0; i < n; i++ {
		var tmp Scalar
		tmp = coeffs[i]
		coeffs[i].Mul(&tmp, &nInv)
	}

	return coeffs
}

// bitLen returns the number of bits required to represent x
func bitLen(x uint32) uint32 {
	var n uint32
	for x > 0 {
		n++
		x >>= 1
	}
	return n
}

// reverseBits reverses the bits of a 32-bit integer
func reverseBits(x uint32) uint32 {
	x = ((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1)
	x = ((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2)
	x = ((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4)
	x = ((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8)
	return (x >> 16) | (x << 16)
}
