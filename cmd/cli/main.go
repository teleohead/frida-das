package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/teleohead/frida-das/pkg/frida"
	"github.com/teleohead/frida-das/sim"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate-data":
		cmdGenerateData(os.Args[2:])
	case "commit":
		cmdCommit(os.Args[2:])
	case "open":
		cmdOpen(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "simulate":
		cmdSimulate(os.Args[2:])
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func parseEvaluator(name string) (frida.PolyEvaluator, error) {
	switch name {
	case "baseline":
		return frida.BaselineEvaluator{}, nil
	default:
		return nil, fmt.Errorf("unknown evaluator %q (available: baseline)", name)
	}
}

func cmdGenerateData(args []string) {
	fs := flag.NewFlagSet("generate-data", flag.ExitOnError)
	size := fs.Int("size", 65536, "data size in bytes")
	out := fs.String("out", "data.bin", "output file path")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "failure: fail to parse args: %v\n", err)
		os.Exit(1)
	}

	data := make([]byte, *size)
	if _, err := rand.Read(data); err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to generate random data: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to write file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("success: generated %d bytes -> %s\n", *size, *out)
}

func cmdCommit(args []string) {
	fs := flag.NewFlagSet("commit", flag.ExitOnError)
	dataPath := fs.String("data", "data.bin", "input data file")
	blowup := fs.Int("blowup", 8, "blowup factor (inverse rate)")
	folding := fs.Int("folding", 4, "folding factor")
	remainder := fs.Int("remainder", 31, "max remainder degree")
	batch := fs.Int("batch", 64, "batch size B")
	queries := fs.Int("queries", 32, "number of query repetitions L")
	evalName := fs.String("eval", "baseline", "polynomial evaluator (baseline)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "failure: fail to parse args: %v\n", err)
		os.Exit(1)
	}

	eval, err := parseEvaluator(*evalName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to read data: %v\n", err)
		os.Exit(1)
	}

	params := frida.Params{
		BlowupFactor:       *blowup,
		FoldingFactor:      *folding,
		MaxRemainderDegree: *remainder,
		BatchSize:          *batch,
		NumQueries:         *queries,
	}

	fmt.Printf("*** committing to %d bytes (blowup=%d, folding=%d, remainder=%d, batch=%d, queries=%d, eval=%s) ***\n",
		len(data), *blowup, *folding, *remainder, *batch, *queries, *evalName)

	startTime := time.Now()
	commitment, proverState, err := params.CommitAndProveWith(data, eval)
	duration := time.Since(startTime)

	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to commit: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("*** commitment finished in %s ***\n", duration)
	fmt.Printf("domain size:    %d\n", proverState.DomainSize)
	fmt.Printf("folding rounds: %d\n", len(proverState.FoldedOracles))
	fmt.Printf("roots:          %d\n", len(commitment.Roots))
	fmt.Printf("final layer:    %d elements\n", len(commitment.FinalLayer))
	fmt.Printf("query proofs:   %d\n", len(commitment.QueryProofs))
}

func cmdOpen(args []string) {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	dataPath := fs.String("data", "data.bin", "input data file")
	blowup := fs.Int("blowup", 8, "blowup factor (inverse rate)")
	folding := fs.Int("folding", 4, "folding factor")
	remainder := fs.Int("remainder", 31, "max remainder degree")
	batch := fs.Int("batch", 64, "batch size B")
	queries := fs.Int("queries", 32, "number of query repetitions L")
	posFlag := fs.String("pos", "0", "comma-separated positions to open (e.g. 0,1,5)")
	evalName := fs.String("eval", "baseline", "polynomial evaluator (baseline)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "failure: fail to parse args: %v\n", err)
		os.Exit(1)
	}

	eval, err := parseEvaluator(*evalName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: %v\n", err)
		os.Exit(1)
	}

	positions, err := parsePositions(*posFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: invalid positions %q: %v\n", *posFlag, err)
		os.Exit(1)
	}

	data, err := os.ReadFile(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to read data: %v\n", err)
		os.Exit(1)
	}

	params := frida.Params{
		BlowupFactor:       *blowup,
		FoldingFactor:      *folding,
		MaxRemainderDegree: *remainder,
		BatchSize:          *batch,
		NumQueries:         *queries,
	}

	_, proverState, err := params.CommitAndProveWith(data, eval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to commit: %v\n", err)
		os.Exit(1)
	}

	startTime := time.Now()
	proof, err := proverState.Open(positions)
	duration := time.Since(startTime)

	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to open: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("*** opened positions %v in %s ***\n", positions, duration)
	fmt.Printf("proof layers:   %d\n", len(proof.Layers))
	totalPaths := 0
	for _, layer := range proof.Layers {
		totalPaths += len(layer.Paths)
	}
	fmt.Printf("total paths:    %d\n", totalPaths)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dataPath := fs.String("data", "data.bin", "input data file")
	blowup := fs.Int("blowup", 8, "blowup factor (inverse rate)")
	folding := fs.Int("folding", 4, "folding factor")
	remainder := fs.Int("remainder", 31, "max remainder degree")
	batch := fs.Int("batch", 64, "batch size B")
	queries := fs.Int("queries", 32, "number of query repetitions L")
	evalName := fs.String("eval", "baseline", "polynomial evaluator (baseline)")
	err := fs.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: fail to parse args: %v\n", err)
		os.Exit(1)
	}

	eval, err := parseEvaluator(*evalName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to read data: %v\n", err)
		os.Exit(1)
	}

	params := frida.Params{
		BlowupFactor:       *blowup,
		FoldingFactor:      *folding,
		MaxRemainderDegree: *remainder,
		BatchSize:          *batch,
		NumQueries:         *queries,
	}

	commitment, _, err := params.CommitAndProveWith(data, eval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to commit: %v\n", err)
		os.Exit(1)
	}

	v, err := frida.NewVerifier(params, commitment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to create verifier: %v\n", err)
		os.Exit(1)
	}

	startTime := time.Now()
	err = v.Verify()
	duration := time.Since(startTime)

	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("VALID: commitment verified in %s\n", duration)
}

func cmdSimulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	dataPath := fs.String("data", "", "input data file (required)")
	nodes := fs.Int("nodes", 50, "number of light nodes")
	samples := fs.Int("samples", 20, "samples per node")
	workers := fs.Int("workers", 0, "network worker goroutines (0 = GOMAXPROCS)")
	blowup := fs.Int("blowup", 8, "blowup factor (inverse rate)")
	folding := fs.Int("folding", 4, "folding factor")
	remainder := fs.Int("remainder", 31, "max remainder degree")
	batch := fs.Int("batch", 64, "batch size B")
	queries := fs.Int("queries", 32, "number of query repetitions L")
	outFile := fs.String("out", "", "write JSON result to file (optional)")
	corruptFlag := fs.String("corrupt", "", "comma-separated positions to corrupt (e.g. 0,1,5)")
	corruptFraction := fs.Float64("corrupt-fraction", 0, "fraction of domain to corrupt (e.g. 0.9)")
	evalName := fs.String("eval", "baseline", "polynomial evaluator (baseline)")
	err := fs.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: fail to parse args: %v\n", err)
		os.Exit(1)
	}

	if *dataPath == "" {
		fmt.Fprintf(os.Stderr, "failure: --data is required\n")
		fs.Usage()
		os.Exit(1)
	}

	eval, err := parseEvaluator(*evalName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to read data: %v\n", err)
		os.Exit(1)
	}

	var corruptPositions []int
	if *corruptFlag != "" {
		corruptPositions, err = parsePositions(*corruptFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failure: invalid corrupt positions %q: %v\n", *corruptFlag, err)
			os.Exit(1)
		}
	}

	params := frida.Params{
		BlowupFactor:       *blowup,
		FoldingFactor:      *folding,
		MaxRemainderDegree: *remainder,
		BatchSize:          *batch,
		NumQueries:         *queries,
	}

	cfg := sim.SimConfig{
		Params:           params,
		Eval:             eval,
		Data:             data,
		NumNodes:         *nodes,
		SamplesPerNode:   *samples,
		NetworkWorkers:   *workers,
		CorruptPositions: corruptPositions,
		CorruptFraction:  *corruptFraction,
	}

	fmt.Printf("Running simulation (%d nodes × %d samples, %d bytes, eval=%s)\n",
		cfg.NumNodes, cfg.SamplesPerNode, len(data), *evalName)

	result, err := sim.RunSimulation(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: simulation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(result)

	if *outFile != "" {
		if err := result.ExportJSON(*outFile); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write JSON: %v\n", err)
		} else {
			fmt.Printf("Wrote %s\n", *outFile)
		}
	}
}

func parsePositions(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	positions := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		positions = append(positions, n)
	}
	return positions, nil
}

func printUsage() {
	fmt.Println(`frida-das CLI

Commands:
  generate-data  Generate random test data
  commit         Run CommitAndProve on a data file
  open           Open a proof at specific positions
  verify         Verify a commitment against committed data
  simulate       Run a full DAS simulation
  help           Show this help

Examples:
  frida-das generate-data --size 65536 --out data.bin
  frida-das commit --data data.bin --blowup 8 --folding 4 --remainder 31 --batch 64 --queries 32
  frida-das commit --data data.bin --eval baseline
  frida-das open --data data.bin --pos 0,1,5 --blowup 8 --folding 4 --remainder 31 --batch 64 --queries 32
  frida-das verify --data data.bin --blowup 8 --folding 4 --remainder 31 --batch 64 --queries 32
  frida-das simulate --data data.bin --nodes 50 --samples 32 --workers 8 --out result.json
  frida-das simulate --data data.bin --nodes 50 --samples 32 --corrupt-fraction 0.9`)
}
