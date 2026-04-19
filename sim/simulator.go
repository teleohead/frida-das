package sim

import (
	"fmt"
	"runtime"
	"time"

	"github.com/teleohead/frida-das/pkg/frida"
)

func RunSimulation(cfg SimConfig) (*SimResult, error) {
	if cfg.NetworkWorkers == 0 {
		cfg.NetworkWorkers = runtime.GOMAXPROCS(0)
	}

	// COMMIT
	tCommitStart := time.Now()

	commitment, prover, err := cfg.Prover.CommitAndProve(cfg.Data)
	if err != nil {
		return nil, fmt.Errorf("commit failed: %w", err)
	}

	verifier, err := cfg.VerifierFactory(commitment)
	if err != nil {
		return nil, fmt.Errorf("verifier construction failed: %w", err)
	}

	commitDuration := time.Since(tCommitStart)

	domainSize := prover.DomainSize
	receptionNeeded := domainSize / prover.Params.BlowupFactor

	// Apply corrupt fraction if no explicit positions provided
	if len(cfg.CorruptPositions) == 0 && cfg.CorruptFraction > 0 {
		n := int(cfg.CorruptFraction * float64(domainSize))
		cfg.CorruptPositions = make([]int, n)
		for i := range cfg.CorruptPositions {
			cfg.CorruptPositions[i] = i
		}
	}

	// SINGLE PROOF METRICS
	proofSampleCount := 10
	if proofSampleCount > domainSize {
		proofSampleCount = domainSize
	}

	var totalProofDuration time.Duration
	var singleProofBytes int

	for i := 0; i < proofSampleCount; i++ {
		pos := i % domainSize
		start := time.Now()
		proof, err := prover.Open([]int{pos})
		totalProofDuration += time.Since(start)
		if err != nil {
			return nil, fmt.Errorf("proof measurement at pos %d: %w", pos, err)
		}
		if i == 0 {
			singleProofBytes = measureProofSize(proof)
		}
	}

	avgProofDuration := totalProofDuration / time.Duration(proofSampleCount)

	// NETWORK SETUP
	numRequests := cfg.NumNodes * cfg.SamplesPerNode
	requestChan := make(chan SampleRequest, numRequests)
	resultChan := make(chan NodeResult, cfg.NumNodes)

	var dp DataProvider

	if len(cfg.CorruptPositions) > 0 {
		dp = NewMaliciousProvider(cfg.CorruptPositions)
	} else {
		dp = NewHonestProvider()
	}

	net := NewNetwork(prover, dp, requestChan, cfg.NetworkWorkers)

	nodes := make([]LightNode, cfg.NumNodes)

	for i := range nodes {
		nodes[i] = LightNode{
			ID:          i,
			NumSamples:  cfg.SamplesPerNode,
			DomainSize:  domainSize,
			Verifier:    verifier,
			RequestChan: requestChan,
			ResultChan:  resultChan,
		}
	}

	// EXEC
	samplingStartTime := time.Now()

	net.Start()

	for i := range nodes {
		go nodes[i].Run()
	}

	nodeResults := make([]NodeResult, cfg.NumNodes)
	for i := 0; i < cfg.NumNodes; i++ {
		nodeResults[i] = <-resultChan
	}

	close(requestChan)

	net.Wait()

	samplingDuration := time.Since(samplingStartTime)

	// ANALYSIS
	totalSampled := 0
	totalAccepted := 0
	totalRejected := 0
	coverageSet := make(map[int]bool, numRequests)
	var totalVerifyNs time.Duration

	for _, nr := range nodeResults {
		totalSampled += len(nr.SampledPositions)
		totalAccepted += nr.AcceptedCount
		totalRejected += nr.RejectedCount
		totalVerifyNs += nr.TotalVerifyNs
		for _, pos := range nr.AcceptedPositions {
			coverageSet[pos] = true
		}
	}

	reconstructable := len(coverageSet) >= receptionNeeded

	var throughput float64
	if samplingDuration > 0 {
		throughput = float64(totalSampled) / samplingDuration.Seconds()
	}

	verifiedCount := totalAccepted + totalRejected
	var avgVerifyDuration time.Duration
	if verifiedCount > 0 {
		avgVerifyDuration = totalVerifyNs / time.Duration(verifiedCount)
	}

	return &SimResult{
		Config:           cfg,
		NodeResults:      nodeResults,
		TotalSampled:     totalSampled,
		TotalAccepted:    totalAccepted,
		TotalRejected:    totalRejected,
		Reconstructable:  reconstructable,
		CommitTimeNs:     commitDuration,
		AvgProofTimeNs:   avgProofDuration,
		AvgVerifyTimeNs:  avgVerifyDuration,
		SingleProofBytes: singleProofBytes,
		SamplingTimeNs:   samplingDuration,
		Throughput:       throughput,
	}, nil

}

func measureProofSize(proof *frida.FriProof) int {
	size := 0
	for _, layer := range proof.Layers {
		for _, path := range layer.Paths {
			size += len(path.LeafValue) + len(path.Siblings) + frida.HashBytes + frida.BytesPerElement
		}
	}
	return size
}
