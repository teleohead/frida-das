package frida

import (
	"fmt"
)

type ProverState struct {
	Params     FriParams
	DomainSize int

	// B interleaved codewords (nil if B = 1)
	BatchOracle []Scalar
	// G_0
	Codeword []Scalar
	// G_1, G_2, ..., G_r
	FoldedOracles [][]Scalar
	// rho_1, rho_2, ... rho_r
	Challenges []Scalar
	// xi
	BatchChallenge Scalar
	// Merkle Trees
	Trees []MerkleTree
}

// Open generates FriProofs for the given positions.
func (prover *ProverState) Open(positions []int) (*FriProof, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("no positions given")
	}
	if len(positions) == 1 {
		return openSingle(prover, positions[0])
	}

	numLayers := len(prover.Trees)
	layers := make([]LayerProof, numLayers)
	for i := range layers {
		layers[i].Paths = make([]MerklePath, 0, len(positions))
	}

	for _, pos := range positions {
		currentPos := pos
		currentDomainSize := prover.DomainSize
		for layer := 0; layer < numLayers; layer++ {
			leafIdx := currentPos % len(prover.Trees[layer].Leaves)
			path := getMerkleProof(prover.Trees[layer], leafIdx)
			layers[layer].Paths = append(layers[layer].Paths, path)
			if layer >= 1 { // fold
				currentDomainSize /= prover.Params.FoldingFactor
				if currentDomainSize > 0 {
					currentPos %= currentDomainSize
				}
			}
		}
	}
	return &FriProof{Layers: layers}, nil
}

// openSingle generates a proof for exactly one position.
// For layer 0 (batch oracle) and layer 1 (G_0): opens the single leaf.
// For layers 2+: opens all F coset preimages so the verifier can check folding consistency via Interpolate.
func openSingle(prover *ProverState, pos int) (*FriProof, error) {
	numLayers := len(prover.Trees)
	layers := make([]LayerProof, numLayers)
	f := prover.Params.FoldingFactor
	preimageBuf := make([]int, f)

	currentPos := pos
	currentDomainSize := prover.DomainSize

	for layer := 0; layer < numLayers; layer++ {
		if layer == 0 {
			// Batch oracle: single path at the queried position.
			leafIdx := currentPos % len(prover.Trees[layer].Leaves)
			path := getMerkleProof(prover.Trees[layer], leafIdx)
			layers[layer] = LayerProof{Paths: []MerklePath{path}}
		} else {
			// G_0 and all folded layers: open F coset preimage paths so the
			// verifier can reconstruct folding consistency for every round.
			cosetPos := currentPos % (currentDomainSize / f)
			writePreimageIndices(cosetPos, currentDomainSize, f, preimageBuf)

			paths := make([]MerklePath, f)
			for k := 0; k < f; k++ {
				leafIdx := preimageBuf[k] % len(prover.Trees[layer].Leaves)
				paths[k] = getMerkleProof(prover.Trees[layer], leafIdx)
			}
			layers[layer] = LayerProof{Paths: paths}
		}

		if layer >= 1 { // G_0 or folded layers
			currentDomainSize /= f
			if currentDomainSize > 0 {
				currentPos = currentPos % currentDomainSize
			}
		}
	}

	return &FriProof{Layers: layers}, nil
}
