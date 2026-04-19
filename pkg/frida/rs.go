package frida

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

// rsBatchEncode encodes B polynomials, see in Section 4.3 of the paper.
// It produces the interleaved codeword.
// This matches the storage.InterleavedSlab layout.
func rsBatchEncode(
	polys [][]Scalar,
	domain []Scalar, // L_0
	out []Scalar, // must be pre-allocated with len = len(polys) * len(domain), interleaved!
	eval PolyEvaluator,
) {
	batchSize := len(polys)   // B
	domainSize := len(domain) // |L_0|
	for j := 0; j < batchSize; j++ {
		evals := eval.Evaluate(polys[j], domain)
		for idx := 0; idx < domainSize; idx++ {
			out[idx*batchSize+j] = evals[idx]
		}
	}
}

// rsEncodeHorner implements Reed-Solomon Encoding with Horner's Method.
// Horner's Method: f(x) = c_0 + x(c_1 + x(c_2 + ...)).
func rsEncodeHorner(
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
