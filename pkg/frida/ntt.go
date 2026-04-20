package frida

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
	// Precompute twiddle factors (powers of omega)
	half := n / 2
	twiddles := make([]Scalar, half)
	twiddles[0].SetOne()
	for k := 1; k < half; k++ {
		twiddles[k].Mul(&twiddles[k-1], &omega)
	}

	for length := 2; length <= n; length *= 2 {
		halfLen := length / 2
		stride := n / length

		for i := 0; i < n; i += length {
			for j := 0; j < halfLen; j++ {
				u := out[i+j]
				var v Scalar
				v.Mul(&out[i+j+halfLen], &twiddles[j*stride])
				out[i+j].Add(&u, &v)
				out[i+j+halfLen].Sub(&u, &v)
			}
		}
	}

	return out
}
