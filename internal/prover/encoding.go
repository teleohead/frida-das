// encoding.go implements the Reed-Solomon encoding and batching logic for the FRI commitment phase.
// This is defined in Section 4.3 and Appendix C.1 of the FRIDA paper.

package prover

import (
	"github.com/teleohead/frida-das/pkg/frida"
)

// BatchCombine computes G_0 = SUM_{j=0}^{B-1} xi^j * G_j for batched FRI.
func BatchCombine(
	interleavedBatch []frida.Scalar, // is in interleaved layout (B * domainSize elements)
	xi *frida.Scalar,                // batching challenge xi
	batchSize int,
	domainSize int,
	out []frida.Scalar, // is the combined codeword G_0, len = domainSize
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
func RSEncodeBatch(
	polys [][]frida.Scalar,
	domain []frida.Scalar, // L_0
	out []frida.Scalar,    // must be pre-allocated with len = len(polys) * len(domain), interleaved!
) {
	batchSize := len(polys)   // B
	domainSize := len(domain) // |L_0|
	buf := make([]frida.Scalar, domainSize)
	for j := 0; j < batchSize; j++ {
		RSEncode(polys[j], domain, buf)
		for idx := 0; idx < domainSize; idx++ {
			out[idx*batchSize+j] = buf[idx]
		}
	}
}

// RSEncode implements Reed-Solomon Encoding.
// We use Horner's Method f(x) = c_0 + x(c_1 + x(c_2 + ...)) to reduce the number of operations.
func RSEncode(
	poly []frida.Scalar, // a polynomial represented by an array of its coefficients
	domain []frida.Scalar,
	out []frida.Scalar, // must be pre-allocated with len = len(domain)
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
