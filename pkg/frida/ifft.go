package frida

import "math/big"

// ifft computes the Inverse Fast Fourier Transform of the given evaluations.
// The length of evals must be a power of 2.
// omegaInv is the inverse primitive root of unity for the domainSize.
func ifft(evals []Scalar, omegaInv Scalar) []Scalar {
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
		tmp := coeffs[i]
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
