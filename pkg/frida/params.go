package frida

import (
	"fmt"
)

type FriParams struct {
	// Blowup factor for the FRI protocol.
	BlowupFactor int
	// Folding factor for the FRI protocol.
	FoldingFactor int
	// Maximum degree of the remainder polynomial.
	MaxRemainderDegree int
	// Number of query-phrase repetitions (L).
	NumQueries int
	// Batch size (B).
	BatchSize int
}

// CommitAndProve executes the full FRI protocol using the default (Horner) evaluator.
func (p *FriParams) CommitAndProve(data []byte) (*Commitment, *ProverState, error) {
	return CommitAndProveWith(*p, data, BaselineEvaluator{})
}

// CommitAndProveWith executes the full FRI protocol using the provided PolyEvaluator.
func CommitAndProveWith(params FriParams, data []byte, eval PolyEvaluator) (*Commitment, *ProverState, error) {
	p := &params
	ff := p.FoldingFactor

	scalars, err := bytesToScalars(data)
	if err != nil {
		return nil, nil, fmt.Errorf("byte-to-scalar data conversion: %w", err)
	}

	if rem := len(scalars) % p.BatchSize; rem != 0 {
		scalars = append(scalars, make([]Scalar, p.BatchSize-rem)...)
	}

	deg := len(scalars) / p.BatchSize
	domainSize := deg * p.BlowupFactor

	polys := make([][]Scalar, p.BatchSize)
	for j := 0; j < p.BatchSize; j++ {
		polys[j] = scalars[j*deg : (j+1)*deg]
	}

	domain := generateDomain(domainSize)
	batchOracle := make([]Scalar, p.BatchSize*domainSize)
	rsEncodeBatch(polys, domain, batchOracle, eval)

	batchLeaves := make([][]byte, domainSize)
	for s := 0; s < domainSize; s++ {
		batchLeaves[s] = serializeSymbol(batchOracle, s, p.BatchSize)
	}
	batchTree := buildMerkleTree(batchLeaves)

	var hst Hash
	hst = chainHash(batchTree.Root, hst, 0)
	xi := deriveFieldChallenge(hst)

	g0 := make([]Scalar, domainSize)
	batchCombine(batchOracle, &xi, p.BatchSize, domainSize, g0)

	g0Leaves := make([][]byte, domainSize)
	for s := 0; s < domainSize; s++ {
		g0Leaves[s] = scalarToBytes(&g0[s])
	}
	g0Tree := buildMerkleTree(g0Leaves)

	numRounds := computeNumRounds(deg, ff, p.MaxRemainderDegree)

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

	prover := &ProverState{
		Params:         *p,
		DomainSize:     domainSize,
		BatchOracle:    batchOracle,
		Codeword:       g0,
		FoldedOracles:  foldedOracles,
		Challenges:     challenges,
		BatchChallenge: xi,
		Trees:          trees,
	}

	queryPositions := deriveQueryPositions(prevRoot, hst, domainSize, p.NumQueries)
	queryProofs := make([]FriProof, p.NumQueries)

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
