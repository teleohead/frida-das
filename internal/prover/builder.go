package prover

import (
	"fmt"

	"github.com/teleohead/frida-das/pkg/frida"
)

// Builder implements frida.FridaBuilder
type Builder struct {
	Params frida.FriParams
}

// NewBuilder initialises a new Builder with the given params.
func NewBuilder(params frida.FriParams) *Builder {
	return &Builder{Params: params}
}

// CommitAndProve executes the full non-interactive Batched FRI protocol.
func (b *Builder) CommitAndProve(data []byte) (*frida.Commitment, *frida.FridaProver, error) {
	params := &b.Params
	ff := params.FoldingFactor

	scalars, err := bytesToScalars(data)
	if err != nil {
		return nil, nil, fmt.Errorf("byte-to-scalar data conversion: %w", err)
	}

	if rem := len(scalars) % params.BatchSize; rem != 0 {
		scalars = append(scalars, make([]frida.Scalar, params.BatchSize-rem)...)
	}

	deg := len(scalars) / params.BatchSize
	domainSize := deg * params.BlowupFactor

	polys := make([][]frida.Scalar, params.BatchSize)
	for j := 0; j < params.BatchSize; j++ {
		polys[j] = scalars[j*deg : (j+1)*deg]
	}

	domain := GenerateDomain(domainSize)
	batchOracle := make([]frida.Scalar, params.BatchSize*domainSize)
	RSEncodeBatch(polys, domain, batchOracle)

	batchLeaves := make([][]byte, domainSize)
	for s := 0; s < domainSize; s++ {
		batchLeaves[s] = serializeSymbol(batchOracle, s, params.BatchSize)
	}
	batchTree := BuildMerkleTree(batchLeaves)

	var hst frida.Hash
	hst = chainHash(batchTree.Root, hst, 0)
	xi := deriveFieldChallenge(hst)

	g0 := make([]frida.Scalar, domainSize)
	BatchCombine(batchOracle, &xi, params.BatchSize, domainSize, g0)

	g0Leaves := make([][]byte, domainSize)
	for s := 0; s < domainSize; s++ {
		g0Leaves[s] = scalarToBytes(&g0[s])
	}
	g0Tree := BuildMerkleTree(g0Leaves)

	numRounds := computeNumRounds(deg, ff, params.MaxRemainderDegree)

	trees := make([]frida.MerkleTree, numRounds+2)
	trees[0] = batchTree
	trees[1] = g0Tree

	foldedOracles := make([][]frida.Scalar, numRounds)
	challenges := make([]frida.Scalar, numRounds)

	scratchPreimage := make([]int, ff)
	scratchXs := make([]frida.Scalar, ff)
	scratchFs := make([]frida.Scalar, ff)
	scratchWeights := make([]frida.Scalar, ff)
	scratchDiffs := make([]frida.Scalar, ff)

	prev := g0
	prevRoot := g0Tree.Root
	currentDomainSize := domainSize

	for r := 0; r < numRounds; r++ {
		hst = chainHash(prevRoot, hst, r+1)
		challenges[r] = deriveFieldChallenge(hst)

		nextDomainSize := currentDomainSize / ff
		next := make([]frida.Scalar, nextDomainSize)
		currentDomain := GenerateDomain(currentDomainSize)

		AlgebraicHash(prev, next, currentDomain, &challenges[r], ff, scratchPreimage, scratchXs, scratchFs, scratchWeights, scratchDiffs)

		foldedOracles[r] = next

		layerLeaves := make([][]byte, nextDomainSize)
		for s := 0; s < nextDomainSize; s++ {
			layerLeaves[s] = scalarToBytes(&next[s])
		}
		layerTree := BuildMerkleTree(layerLeaves)
		trees[r+2] = layerTree

		prevRoot = layerTree.Root
		prev = next
		currentDomainSize = nextDomainSize
	}

	finalLayer := prev

	prover := &frida.FridaProver{
		Params:         *params,
		DomainSize:     domainSize,
		BatchOracle:    batchOracle,
		Codeword:       g0,
		FoldedOracles:  foldedOracles,
		Challenges:     challenges,
		BatchChallenge: xi,
		Trees:          trees,
	}

	queryPositions := deriveQueryPositions(prevRoot, hst, domainSize, params.NumQueries)
	queryProofs := make([]frida.FriProof, params.NumQueries)

	for i, pos := range queryPositions {
		proof, err := openSingle(prover, pos)
		if err != nil {
			return nil, nil, fmt.Errorf("query proof at position %d: %w", pos, err)
		}
		if proof == nil {
			return nil, nil, fmt.Errorf("received nil proof without an error at position %d", pos)
		}
		queryProofs[i] = *proof
	}

	roots := make([]frida.Hash, len(trees))
	for i := range trees {
		roots[i] = trees[i].Root
	}

	comm := &frida.Commitment{
		Roots:          roots,
		FinalLayer:     finalLayer,
		QueryProofs:    queryProofs,
		QueryPositions: queryPositions,
	}

	return comm, prover, nil
}
