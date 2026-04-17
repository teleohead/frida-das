package frida

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// builds verifier from commitment and params
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

// checks embedded query proofs
func (v *Verifier) VerifyCommitmentProofs() error {
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
			return fmt.Errorf("query %d (pos %d): %w", i, pos, err)
		}
	}
	return nil
}

// checks a single DAS sample
func (v *Verifier) VerifySample(pos int, proof *FriProof, evals []Scalar) error {
	if err := v.verifyMerklePaths(pos, proof); err != nil {
		return err
	}
	return v.verifyBatchCombine(proof, evals)
}

// checks merkle paths
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
			if want := currentPos % path.NumLeaves; path.Index != want {
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
func (v *Verifier) verifyBatchCombine(proof *FriProof, evals []Scalar) error {
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

	g0Leaf := proof.Layers[1].Paths[0].LeafValue
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
