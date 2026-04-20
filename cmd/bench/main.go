package main

import (
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/teleohead/frida-das/pkg/frida"
)

type friOption struct {
	blowup    int
	folding   int
	remainder int
}

const (
	commitRuns = 3
	proofRuns  = 10
	verifyRuns = 10
)

var queryCounts = [3]int{1, 16, 32}

func main() {
	friOpts := flag.String("fri-options", "2,2,0", "semicolon-separated blowup,folding,remainder tuples e.g. '2,2,0;4,2,0'")
	dataSizes := flag.String("data-sizes", "131072,262144,524288,1048576,2097152", "comma-separated data sizes in bytes")
	batchSizesFlag := flag.String("batch-sizes", "1,4,16,32", "comma-separated batch sizes")
	numQueries := flag.Int("num-queries", 30, "FRI NumQueries param (L)")
	evaluatorName := flag.String("evaluator", "baseline", "polynomial evaluator: baseline (horner) or ntt")
	output := flag.String("output", "bench_results.csv", "path to CSV output file")
	evaluator := flag.String("evaluator", "baseline", "evaluator to use: baseline or ntt")
	flag.Parse()

	options, err := parseFriOptions(*friOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse --fri-options: %v\n", err)
		os.Exit(1)
	}
	sizes, err := parseInts(*dataSizes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse --data-sizes: %v\n", err)
		os.Exit(1)
	}
	batches, err := parseInts(*batchSizesFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse --batch-sizes: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	w := csv.NewWriter(f)

	header := []string{
		"field_type", "batch_size", "blowup_factor", "folding_factor", "max_remainder_degree", "data_size_kb", "num_queries",
		"erasure_time_ms", "commitment_time_ms", "proof_time_1_ms", "proof_time_16_ms", "proof_time_32_ms",
		"verification_setup_ms", "verification_1_ms", "verification_16_ms", "verification_32_ms",
		"commitment_size_bytes", "proof_size_1_bytes", "proof_size_16_bytes", "proof_size_32_bytes",
	}
	if err := w.Write(header); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write csv header: %v\n", err)
		os.Exit(1)
	}

	eval, err := parseEvaluator(*evaluatorName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse --evaluator: %v\n", err)
		os.Exit(1)
	}

	for _, option := range options {
		for _, dataSize := range sizes {
			for _, batchSize := range batches {
				params := frida.Params{
					BlowupFactor:       option.blowup,
					FoldingFactor:      option.folding,
					MaxRemainderDegree: option.remainder,
					NumQueries:         *numQueries,
					BatchSize:          batchSize,
				}

				data := make([]byte, dataSize)
				if _, err := rand.Read(data); err != nil {
					fmt.Fprintf(os.Stderr, "failed to perform rand.Read: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("running benchmark: blowup=%d folding=%d remainder=%d data=%dKB batch=%d queries=%d\n",
					option.blowup, option.folding, option.remainder, dataSize/1024, batchSize, *numQueries)

				if _, _, err := params.CommitAndProveWith(data, eval); err != nil {
					fmt.Fprintf(os.Stderr, "failed during warmup commit: %v\n", err)
					os.Exit(1)
				}

				var totalCommitDuration time.Duration
				var commitment *frida.Commitment
				var prover *frida.ProverState
				for i := 0; i < commitRuns; i++ {
					start := time.Now()
					c, p, err := params.CommitAndProveWith(data, eval)
					totalCommitDuration += time.Since(start)
					if err != nil {
						fmt.Fprintf(os.Stderr, "failed during commit run %d: %v\n", i, err)
						os.Exit(1)
					}
					commitment, prover = c, p
				}
				commitMs := toMs(totalCommitDuration) / commitRuns

				var totalErasureDuration time.Duration
				for i := 0; i < commitRuns; i++ {
					start := time.Now()
					if _, _, err := params.Encode(data, eval); err != nil {
						fmt.Fprintf(os.Stderr, "failed during erasure run %d: %v\n", i, err)
						os.Exit(1)
					}
					totalErasureDuration += time.Since(start)
				}
				erasureMs := toMs(totalErasureDuration) / commitRuns

				domainSize := prover.DomainSize

				var proofMs [3]float64
				var proofSizes [3]int
				for qi, qc := range queryCounts {
					positions := makePositions(qc, domainSize)
					if _, err := prover.Open(positions); err != nil { // warmup
						fmt.Fprintf(os.Stderr, "failed during warmup open q=%d: %v\n", qc, err)
						os.Exit(1)
					}
					var total time.Duration
					var lastProof *frida.Proof
					for i := 0; i < proofRuns; i++ {
						start := time.Now()
						p, err := prover.Open(positions)
						total += time.Since(start)
						if err != nil {
							fmt.Fprintf(os.Stderr, "failed during open run %d q=%d: %v\n", i, qc, err)
							os.Exit(1)
						}
						lastProof = p
					}
					proofMs[qi] = toMs(total) / proofRuns
					proofSizes[qi] = lastProof.ByteSize()
				}

				commitmentBytes := commitment.ByteSize()

				var totalSetupDuration time.Duration
				var verifier *frida.Verifier
				for i := 0; i < verifyRuns; i++ {
					start := time.Now()
					v, err := frida.NewVerifier(params, commitment)
					totalSetupDuration += time.Since(start)
					if err != nil {
						fmt.Fprintf(os.Stderr, "failed during new verifier run %d: %v\n", i, err)
						os.Exit(1)
					}
					verifier = v
				}
				setupMs := toMs(totalSetupDuration) / verifyRuns

				var verifyMs [3]float64
				for qi, qc := range queryCounts {
					positions := makePositions(qc, domainSize)
					proofs, _ := openEach(prover, positions)
					evalSets := evalsAt(prover, positions)

					for k, pos := range positions {
						err := verifier.VerifySample(pos, proofs[k], evalSets[k])
						if err != nil {
							fmt.Fprintf(os.Stderr, "failed to verify sample at pos %d: %v\n", pos, err)
						}
					}

					var total time.Duration
					for i := 0; i < verifyRuns; i++ {
						start := time.Now()
						for k, pos := range positions {
							_ = verifier.VerifySample(pos, proofs[k], evalSets[k])
						}
						total += time.Since(start)
					}
					verifyMs[qi] = toMs(total) / verifyRuns
				}

				row := []string{
					"goldilocks_f64_" + *evaluatorName,
					strconv.Itoa(batchSize),
					strconv.Itoa(option.blowup),
					strconv.Itoa(option.folding),
					strconv.Itoa(option.remainder),
					strconv.Itoa(dataSize / 1024),
					strconv.Itoa(*numQueries),
					formatFloat(erasureMs),
					formatFloat(commitMs),
					formatFloat(proofMs[0]), formatFloat(proofMs[1]), formatFloat(proofMs[2]),
					formatFloat(setupMs),
					formatFloat(verifyMs[0]), formatFloat(verifyMs[1]), formatFloat(verifyMs[2]),
					strconv.Itoa(commitmentBytes),
					strconv.Itoa(proofSizes[0]), strconv.Itoa(proofSizes[1]), strconv.Itoa(proofSizes[2]),
				}
				if err := w.Write(row); err != nil {
					fmt.Fprintf(os.Stderr, "failed to write csv row: %v\n", err)
					os.Exit(1)
				}
				w.Flush()
			}
		}
	}

	fmt.Printf("success: results written to %s\n", *output)
}

// openEach opens each position individually and returns one corresponding proof per position
func openEach(prover *frida.ProverState, positions []int) ([]*frida.Proof, error) {
	proofs := make([]*frida.Proof, len(positions))

	for i, pos := range positions {
		p, err := prover.OpenSingle(pos)
		if err != nil {
			return nil, fmt.Errorf("failed to open at pos %d: %w", pos, err)
		}
		proofs[i] = p
	}

	return proofs, nil
}

// evalsAt extracts the batch oracle evaluations at each position.
// Returns zero-allocation views into the prover's BatchOracle (read-only).
func evalsAt(prover *frida.ProverState, positions []int) [][]frida.Scalar {
	batchSize := prover.Params.BatchSize
	out := make([][]frida.Scalar, len(positions))
	for i, pos := range positions {
		start := pos * batchSize
		out[i] = prover.BatchOracle[start : start+batchSize]
	}
	return out
}

func makePositions(count, domainSize int) []int {
	if count > domainSize {
		count = domainSize
	}
	pos := make([]int, count)
	for i := range pos {
		pos[i] = i
	}
	return pos
}

// toMs converts a duration to milliseconds as float64.
func toMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1e6
}

// formatFloat formats a float with 3 decimal places.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 3, 64)
}

func parseEvaluator(name string) (frida.PolyEvaluator, error) {
	switch name {
	case "baseline":
		return frida.BaselineEvaluator{}, nil
	case "ntt":
		return frida.NTTEvaluator{}, nil
	default:
		return nil, fmt.Errorf("unknown evaluator %q (available: baseline, ntt)", name)
	}
}

func parseFriOptions(s string) ([]friOption, error) {
	var options []friOption
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		nums, err := parseInts(part)
		if err != nil || len(nums) != 3 {
			return nil, fmt.Errorf("failure: invalid fri option %q (want blowup,folding,remainder)", part)
		}
		options = append(options, friOption{nums[0], nums[1], nums[2]})
	}
	if len(options) == 0 {
		return nil, fmt.Errorf("failure: no fri options parsed from %q", s)
	}
	return options, nil
}

func parseInts(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
