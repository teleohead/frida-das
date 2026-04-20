package frida

import (
	"fmt"
)

type Params struct {
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

// CommitAndProveWith executes the full FRI protocol using the provided PolyEvaluator.
func (params Params) CommitAndProveWith(data []byte, eval PolyEvaluator) (*Commitment, *ProverState, error) {
	domain, batchOracle, err := params.Encode(data, eval)
	if err != nil {
		return nil, nil, err
	}
	return params.commitFromOracle(domain, batchOracle)
}

// Encode performs only the Reed-Solomon erasure coding step on data.
// Returns the evaluation domain and the interleaved batch oracle.
func (params Params) Encode(data []byte, eval PolyEvaluator) ([]Scalar, []Scalar, error) {
	scalars, err := bytesToScalars(data)
	if err != nil {
		return nil, nil, fmt.Errorf("byte-to-scalar conversion: %w", err)
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
	rsBatchEncode(polys, domain, batchOracle, eval)
	return domain, batchOracle, nil
}

// commitFromOracle builds the full FRI commitment from a pre-encoded domain and batch oracle.
func (params Params) commitFromOracle(domain []Scalar, batchOracle []Scalar) (*Commitment, *ProverState, error) {
	p := &params
	ff := p.FoldingFactor
	domainSize := len(domain)
	deg := domainSize / p.BlowupFactor

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
	queryProofs := make([]Proof, p.NumQueries)

	for i, pos := range queryPositions {
		proof, err := prover.OpenSingle(pos)
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
