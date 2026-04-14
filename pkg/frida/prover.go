package frida

import (
	"fmt"
)

// Open generates FriProofs for the given positions.
func (prover *Prover) Open(positions []int) (*FriProof, error) {
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
func openSingle(prover *Prover, pos int) (*FriProof, error) {
	numLayers := len(prover.Trees)
	layers := make([]LayerProof, numLayers)

	currentPos := pos
	currentDomainSize := prover.DomainSize

	for layer := 0; layer < numLayers; layer++ {
		leafIdx := currentPos % len(prover.Trees[layer].Leaves)
		path := getMerkleProof(prover.Trees[layer], leafIdx)
		layers[layer] = LayerProof{Paths: []MerklePath{path}}
		if layer >= 1 { // G_0 or folded layers
			currentDomainSize /= prover.Params.FoldingFactor
			if currentDomainSize > 0 {
				currentPos = currentPos % currentDomainSize
			}
		}
	}

	return &FriProof{Layers: layers}, nil

}
