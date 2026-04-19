package frida

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
)

// NewVerifier builds verifier from commitment and params
func NewVerifier(params FriParams, commitment *Commitment) (*Verifier, error) {
	if len(commitment.Roots) < 2 {
		return nil, fmt.Errorf("need at least 2 roots, got %d", len(commitment.Roots))
	}

	numRounds := len(commitment.Roots) - 2

	// finalLayer has domainSize / F^numRounds elements, so work backwards.
	domainSize := len(commitment.FinalLayer)
	for r := 0; r < numRounds; r++ {
		domainSize *= params.FoldingFactor
	}

	hst := chainHash(commitment.Roots[0], Hash{}, 0)
	challenges := make([]Scalar, numRounds)
	for r := 0; r < numRounds; r++ {
		hst = chainHash(commitment.Roots[r+1], hst, r+1)
		challenges[r] = deriveFieldChallenge(hst)
	}

	return &Verifier{
		Params:     params,
		Commitment: commitment,
		Challenges: challenges,
		DomainSize: domainSize,
	}, nil
}

// Verify checks embedded query proofs
func (v *Verifier) Verify() error {
	if err := v.verifyDegreeBound(); err != nil {
		return fmt.Errorf("proof with invalid degree bound: %w", err)
	}

	numRounds := len(v.Commitment.Roots) - 2

	hst := chainHash(v.Commitment.Roots[0], Hash{}, 0)
	for r := 0; r < numRounds; r++ {
		hst = chainHash(v.Commitment.Roots[r+1], hst, r+1)
	}

	finalRoot := v.Commitment.Roots[len(v.Commitment.Roots)-1]
	expected := deriveQueryPositions(finalRoot, hst, v.DomainSize, v.Params.NumQueries)

	if len(v.Commitment.QueryPositions) != len(expected) {
		return fmt.Errorf("wrong number of query positions: got %d, want %d",
			len(v.Commitment.QueryPositions), len(expected))
	}

	for i, pos := range v.Commitment.QueryPositions {
		if pos != expected[i] {
			return fmt.Errorf("query %d: position %d doesn't match Fiat-Shamir (%d)", i, pos, expected[i])
		}
		if err := v.verifyMerklePaths(pos, &v.Commitment.QueryProofs[i]); err != nil {
			return fmt.Errorf("query %d (pos %d) merkle path check failed: %w", i, pos, err)
		}
		if err := v.verifyFoldingConsistency(pos, &v.Commitment.QueryProofs[i]); err != nil {
			return fmt.Errorf("query %d (pos %d) folding failed: %w", i, pos, err)
		}
	}
	return nil
}

// checks a single DAS sample
func (v *Verifier) VerifySample(pos int, proof *FriProof, evals []Scalar) error {
	if err := v.verifyMerklePaths(pos, proof); err != nil {
		return err
	}
	if err := v.verifyBatchCombine(pos, proof, evals); err != nil {
		return err
	}
	return v.verifyFoldingConsistency(pos, proof)
}

// checks Merkle paths
func (v *Verifier) verifyMerklePaths(pos int, proof *FriProof) error {
	if len(proof.Layers) != len(v.Commitment.Roots) {
		return fmt.Errorf("proof has %d layers but commitment has %d roots",
			len(proof.Layers), len(v.Commitment.Roots))
	}

	currentPos := pos
	currentDomainSize := v.DomainSize

	for layer, lp := range proof.Layers {
		root := v.Commitment.Roots[layer]
		for _, path := range lp.Paths {
			if path.NumLeaves == 0 {
				return fmt.Errorf("layer %d: path has zero leaves", layer)
			}
			stride := path.NumLeaves / len(lp.Paths)
			if stride == 0 {
				stride = 1
			}
			if want := currentPos % stride; path.Index%stride != want {
				return fmt.Errorf("layer %d: path index %d, expected %d", layer, path.Index, want)
			}
			if !VerifyMerkleProof(root, path) {
				return fmt.Errorf("layer %d: merkle proof failed at pos %d", layer, currentPos)
			}
		}
		// the batch oracle and G_0 both live over L_0, so folding only starts
		// after layer 1.
		if layer >= 1 {
			currentDomainSize /= v.Params.FoldingFactor
			if currentDomainSize > 0 {
				currentPos %= currentDomainSize
			}
		}
	}
	return nil
}

// checks batch combine
func (v *Verifier) verifyBatchCombine(pos int, proof *FriProof, evals []Scalar) error {
	if len(evals) != v.Params.BatchSize {
		return fmt.Errorf("got %d evals, want %d", len(evals), v.Params.BatchSize)
	}
	if len(proof.Layers) < 2 ||
		len(proof.Layers[0].Paths) == 0 ||
		len(proof.Layers[1].Paths) == 0 {
		return nil
	}

	// check that the supplied evals with leaf
	batchLeaf := proof.Layers[0].Paths[0].LeafValue
	want := make([]byte, v.Params.BatchSize*BytesPerElement)
	for j, e := range evals {
		binary.LittleEndian.PutUint64(want[j*BytesPerElement:], e.Uint64())
	}
	if !bytes.Equal(batchLeaf, want) {
		return fmt.Errorf("evals don't match the batch oracle leaf")
	}

	// xi and compute the expected G_0
	hst := chainHash(v.Commitment.Roots[0], Hash{}, 0)
	xi := deriveFieldChallenge(hst)

	last := v.Params.BatchSize - 1
	var expected Scalar
	expected = evals[last]
	for j := last - 1; j >= 0; j-- {
		var tmp Scalar
		tmp.Mul(&expected, &xi)
		expected.Add(&tmp, &evals[j])
	}

	// Layer 1 (G_0) now holds F coset paths; find the one for pos.
	var g0Leaf []byte
	for _, p := range proof.Layers[1].Paths {
		if p.Index == pos {
			g0Leaf = p.LeafValue
			break
		}
	}
	if g0Leaf == nil {
		return fmt.Errorf("no G_0 path found for position %d", pos)
	}
	if len(g0Leaf) < BytesPerElement {
		return fmt.Errorf("G_0 leaf too short (%d bytes)", len(g0Leaf))
	}
	var got Scalar
	got.SetUint64(binary.LittleEndian.Uint64(g0Leaf[:BytesPerElement]))

	if got != expected {
		return fmt.Errorf("G_0 value doesn't match the batch combination of the supplied evals")
	}
	return nil
}

// verifyFoldingConsistency verifies folding consistency. this corresponds to the CheckAuth phase from the paper.
func (v *Verifier) verifyFoldingConsistency(pos int, proof *FriProof) error {
	numRounds := len(v.Challenges)
	F := v.Params.FoldingFactor

	// scratch buffers
	xs := make([]Scalar, F)
	fs := make([]Scalar, F)
	weights := make([]Scalar, F)
	diffs := make([]Scalar, F)
	preimageBuf := make([]int, F)

	currentPos := pos
	currentDomainSize := v.DomainSize

	for round := 0; round < numRounds; round++ {
		prevLayerIdx := round + 1
		nextLayerIdx := round + 2

		if prevLayerIdx >= len(proof.Layers) || nextLayerIdx >= len(proof.Layers) {
			return fmt.Errorf("round %d: proof missing layers (have %d, need %d)",
				round, len(proof.Layers), nextLayerIdx+1)
		}

		// we compute only the F coset domain points (not the full domain)
		omega := primitiveRoot(currentDomainSize)
		stride := currentDomainSize / F

		cosetPos := currentPos % stride
		writePreimageIndices(cosetPos, currentDomainSize, F, preimageBuf)

		// xs[0] = omega ^ preimageBuf[0], then multiply omega^stride for each next
		xs[0].Exp(omega, new(big.Int).SetUint64(uint64(preimageBuf[0])))
		var omegaStride Scalar
		omegaStride.Exp(omega, new(big.Int).SetUint64(uint64(stride)))
		for k := 1; k < F; k++ {
			xs[k].Mul(&xs[k-1], &omegaStride)
		}

		// extract evaluations from the previous layer's coset paths
		prevLayer := proof.Layers[prevLayerIdx]
		if len(prevLayer.Paths) < F {
			return fmt.Errorf("round %d: need %d coset paths at layer %d, got %d",
				round, F, prevLayerIdx, len(prevLayer.Paths))
		}

		for k := 0; k < F; k++ {
			leaf := prevLayer.Paths[k].LeafValue
			if len(leaf) < BytesPerElement {
				return fmt.Errorf("round %d coset %d: leaf too short (%d bytes)",
					round, k, len(leaf))
			}
			fs[k].SetUint64(binary.LittleEndian.Uint64(leaf[:BytesPerElement]))
		}

		// interpolate and compare against the next layer
		expected := interpolate(&v.Challenges[round], xs[:F], fs[:F], weights, diffs)
		nextLayer := proof.Layers[nextLayerIdx]
		nextDomainSize := currentDomainSize / F
		targetIdx := currentPos % nextDomainSize

		var actual Scalar
		found := false
		for _, p := range nextLayer.Paths {
			if p.Index == targetIdx {
				if len(p.LeafValue) < BytesPerElement {
					return fmt.Errorf("round %d: next layer leaf too short (%d bytes)",
						round, len(p.LeafValue))
				}
				actual.SetUint64(binary.LittleEndian.Uint64(p.LeafValue[:BytesPerElement]))
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("round %d: no path in layer %d for folded position %d",
				round, nextLayerIdx, targetIdx)
		}

		if expected != actual {
			return fmt.Errorf("round %d: folding consistency failed at pos %d (expected %d, got %d)",
				round, currentPos, expected.Uint64(), actual.Uint64())
		}

		currentDomainSize = nextDomainSize
		currentPos = targetIdx
	}

	// check final layer
	if err := v.verifyFinalLayer(currentPos, proof); err != nil {
		return err
	}

	return nil
}

// verifyFinalLayer checks that the last folded value matches the commitment's FinalLayer.
func (v *Verifier) verifyFinalLayer(finalPos int, proof *FriProof) error {
	if len(v.Commitment.FinalLayer) == 0 {
		return fmt.Errorf("commitment has empty final layer")
	}

	idx := finalPos % len(v.Commitment.FinalLayer)
	lastLayer := proof.Layers[len(proof.Layers)-1]

	var actual Scalar
	found := false

	for _, p := range lastLayer.Paths {
		if p.Index == idx {
			if len(p.LeafValue) < BytesPerElement {
				return fmt.Errorf("final layer leaf too short")
			}
			actual.SetUint64(binary.LittleEndian.Uint64(p.LeafValue[:BytesPerElement]))
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no path in final proof layer for index %d", idx)
	}

	if actual != v.Commitment.FinalLayer[idx] {
		return fmt.Errorf("final layer mismatch at pos %d: proof=%v, commitment=%v",
			idx, actual.Uint64(), v.Commitment.FinalLayer[idx].Uint64())
	}

	return nil
}

func (v *Verifier) verifyDegreeBound() error {
	finalEvals := v.Commitment.FinalLayer
	n := len(finalEvals)
	// trivially valid if length of final evaluations is already under max_remainder_deg + 1
	if n <= v.Params.MaxRemainderDegree+1 {
		return nil
	}

	// calculate ω^-1 using Fermat's Little Theorem
	// a^(p-2) mod p == a^-1 mod p
	omega := primitiveRoot(n)
	pm2 := uint64(GoldilocksPrime - 2)
	var omegaInv Scalar
	omegaInv.Exp(omega, new(big.Int).SetUint64(pm2))

	// perform inverse FFT
	coeffs := iFFT(finalEvals, omegaInv)

	// all degrees above max_remainder_degree must be zero
	var zero Scalar
	for i := v.Params.MaxRemainderDegree + 1; i < n; i++ {
		if coeffs[i] != zero {
			return fmt.Errorf("degree bound failed: coefficient %d is not zero", i)
		}
	}

	return nil
}
