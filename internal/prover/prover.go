package prover

import (
	"fmt"

	"github.com/teleohead/frida-das/pkg/frida"
)

// Open generates FriProofs for the given positions.
func Open(prover *frida.FridaProver, positions []int) (*frida.FriProof, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("no positions given")
	}
	if len(positions) == 1 {
		return openSingle(prover, positions[0])
	}

	numLayers := len(prover.Trees)
	layers := make([]frida.LayerProof, numLayers)
	for i := range layers {
		layers[i].Paths = make([]frida.MerklePath, 0, len(positions))
	}

	for _, pos := range positions {
		currentPos := pos
		currentDomainSize := prover.DomainSize
		for layer := 0; layer < numLayers; layer++ {
			leafIdx := currentPos % len(prover.Trees[layer].Leaves)
			path := GetMerkleProof(prover.Trees[layer], leafIdx)
			layers[layer].Paths = append(layers[layer].Paths, path)
			if layer >= 1 { // fold
				currentDomainSize /= prover.Params.FoldingFactor
				if currentDomainSize > 0 {
					currentPos %= currentDomainSize
				}
			}
		}
	}
	return &frida.FriProof{Layers: layers}, nil
}

// openSingle generates a proof for exactly one position.
func openSingle(prover *frida.FridaProver, pos int) (*frida.FriProof, error) {
	numLayers := len(prover.Trees)
	layers := make([]frida.LayerProof, numLayers)

	currentPos := pos
	currentDomainSize := prover.DomainSize

	for layer := 0; layer < numLayers; layer++ {
		leafIdx := currentPos % len(prover.Trees[layer].Leaves)
		path := GetMerkleProof(prover.Trees[layer], leafIdx)
		layers[layer] = frida.LayerProof{Paths: []frida.MerklePath{path}}
		if layer >= 1 { // G_0 or folded layers
			currentDomainSize /= prover.Params.FoldingFactor
			if currentDomainSize > 0 {
				currentPos = currentPos % currentDomainSize
			}
		}
	}

	return &frida.FriProof{Layers: layers}, nil

}
