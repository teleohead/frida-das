package frida

import (
	"fmt"
)

// Builder implements frida.FridaBuilder
type Builder struct {
	Params FriParams
}

// NewBuilder initialises a new Builder with the given params.
func NewBuilder(params FriParams) *Builder {
	return &Builder{Params: params}
}

// CommitAndProve executes the full non-interactive Batched FRI protocol.
func (b *Builder) CommitAndProve(data []byte) (*Commitment, *Prover, error) {
	params := &b.Params
	ff := params.FoldingFactor

	scalars, err := bytesToScalars(data)
	if err != nil {
		return nil, nil, fmt.Errorf("byte-to-scalar data conversion: %w", err)
	}

	if rem := len(scalars) % params.BatchSize; rem != 0 {
		scalars = append(scalars, make([]Scalar, params.BatchSize-rem)...)
	}

	deg := len(scalars) / params.BatchSize
	domainSize := deg * params.BlowupFactor

	polys := make([][]Scalar, params.BatchSize)
	for j := 0; j < params.BatchSize; j++ {
		polys[j] = scalars[j*deg : (j+1)*deg]
	}

	domain := generateDomain(domainSize)
	batchOracle := make([]Scalar, params.BatchSize*domainSize)
	rsEncodeBatch(polys, domain, batchOracle)

	batchLeaves := make([][]byte, domainSize)
	for s := 0; s < domainSize; s++ {
		batchLeaves[s] = serializeSymbol(batchOracle, s, params.BatchSize)
	}
	batchTree := buildMerkleTree(batchLeaves)

	var hst Hash
	hst = chainHash(batchTree.Root, hst, 0)
	xi := deriveFieldChallenge(hst)

	g0 := make([]Scalar, domainSize)
	batchCombine(batchOracle, &xi, params.BatchSize, domainSize, g0)

	g0Leaves := make([][]byte, domainSize)
	for s := 0; s < domainSize; s++ {
		g0Leaves[s] = scalarToBytes(&g0[s])
	}
	g0Tree := buildMerkleTree(g0Leaves)

	numRounds := computeNumRounds(deg, ff, params.MaxRemainderDegree)

	trees := make([]MerkleTree, numRounds+2)
	trees[0] = batchTree
	trees[1] = g0Tree

	foldedOracles := make([][]Scalar, numRounds)
	challenges := make([]Scalar, numRounds)

	scratchPreimage := make([]int, ff)
	scratchXs := make([]Scalar, ff)
	scratchFs := make([]Scalar, ff)
	scratchWeights := make([]Scalar, ff)
	scratchDiffs := make([]Scalar, ff)

	prev := g0
	prevRoot := g0Tree.Root
	currentDomainSize := domainSize

	for r := 0; r < numRounds; r++ {
		hst = chainHash(prevRoot, hst, r+1)
		challenges[r] = deriveFieldChallenge(hst)

		nextDomainSize := currentDomainSize / ff
		next := make([]Scalar, nextDomainSize)
		currentDomain := generateDomain(currentDomainSize)

		algebraicHash(prev, next, currentDomain, &challenges[r], ff, scratchPreimage, scratchXs, scratchFs, scratchWeights, scratchDiffs)

		foldedOracles[r] = next

		layerLeaves := make([][]byte, nextDomainSize)
		for s := 0; s < nextDomainSize; s++ {
			layerLeaves[s] = scalarToBytes(&next[s])
		}
		layerTree := buildMerkleTree(layerLeaves)
		trees[r+2] = layerTree

		prevRoot = layerTree.Root
		prev = next
		currentDomainSize = nextDomainSize
	}

	finalLayer := prev

	prover := &Prover{
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
	queryProofs := make([]FriProof, params.NumQueries)

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

	roots := make([]Hash, len(trees))
	for i := range trees {
		roots[i] = trees[i].Root
	}

	comm := &Commitment{
		Roots:          roots,
		FinalLayer:     finalLayer,
		QueryProofs:    queryProofs,
		QueryPositions: queryPositions,
	}

	return comm, prover, nil
}
