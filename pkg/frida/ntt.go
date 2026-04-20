package frida

import "math/big"

// ntt computes the Number Theoretic Transform of the given coefficients.
// O(nlog n) time complexity.
// Using the Cooley-Tukey algorithm.
// The length of coeffs must be a power of 2.
// omega is the primitive root of unity for the domainSize.
func ntt(coeffs []Scalar, omega Scalar) []Scalar {
	n := len(coeffs)
	if n == 0 {
		return nil
	}

	// 1. Bit-reversal permutation (in-place copy)
	out := make([]Scalar, n)
	shift := 32 - bitLen(uint32(n-1))
	for i := 0; i < n; i++ {
		rev := reverseBits(uint32(i)) >> shift
		out[rev] = coeffs[i]
	}

	// 2. Cooley-Tukey iterative iFFT
	for length := 2; length <= n; length *= 2 {
		half := length / 2

		// omegaStep = omegaInv ^ (n / length)
		var omegaStep Scalar
		exp := uint64(n / length)
		omegaStep.Exp(omega, new(big.Int).SetUint64(exp))

		for i := 0; i < n; i += length {
			var w Scalar
			w.SetOne()
			for j := 0; j < half; j++ {
				u := out[i+j]
				var v, tmp Scalar
				// v = w * out[i+j+half]
				tmp = out[i+j+half]
				v.Mul(&tmp, &w)
				// out[i+j] = u + v
				out[i+j].Add(&u, &v)
				// out[i+j+half] = u - v
				out[i+j+half].Sub(&u, &v)
				// w = w * omegaStep
				tmp = w
				w.Mul(&tmp, &omegaStep)
			}
		}
	}

	return out
}
