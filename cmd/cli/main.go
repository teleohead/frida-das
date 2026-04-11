package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/teleohead/frida-das/internal/prover"
	"github.com/teleohead/frida-das/pkg/frida"
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

func cmdGenerateData(args []string) {
	fs := flag.NewFlagSet("generate-data", flag.ExitOnError)
	size := fs.Int("size", 65536, "data size in bytes")
	out := fs.String("out", "data.bin", "output file path")
	fs.Parse(args)

	data := make([]byte, *size)

	_, err := rand.Read(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to generate random data: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(*out, data, 0644)
	if err != nil {
		fmt.Fprint(os.Stderr, "failure: failed to write file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("success: generated %d bytes -> %s \n", *size, *out)
}

func cmdCommit(args []string) {
	fs := flag.NewFlagSet("commit", flag.ExitOnError)
	dataPath := fs.String("data", "data.bin", "input data file")
	blowup := fs.Int("blowup", 8, "blowup factor (inverse rate)")
	folding := fs.Int("folding", 4, "folding factor")
	remainder := fs.Int("remainder", 31, "max remainder degree")
	batch := fs.Int("batch", 64, "batch size B")
	queries := fs.Int("queries", 32, "number of query repetitions L")
	fs.Parse(args)

	data, err := os.ReadFile(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure: failed to read data: %v\n", err)
		os.Exit(1)
	}

	params := frida.FriParams{
		BlowupFactor:       *blowup,
		FoldingFactor:      *folding,
		MaxRemainderDegree: *remainder,
		BatchSize:          *batch,
		NumQueries:         *queries,
	}

	builder := prover.NewBuilder(params)

	fmt.Printf("*** committing to %d bytes (blowup=%d, folding=%d, remainder=%d, batch=%d, queries=%d) ***\n",
		len(data), *blowup, *folding, *remainder, *batch, *queries)

	startTime := time.Now()
	commitment, proverState, err := builder.CommitAndProve(data)
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

}

func cmdSimulate(args []string) {

}

func printUsage() {
	fmt.Println(`frida-das CLI
 
Commands:
  generate-data  Generate random test data
  commit         Run CommitAndProve on a data file
  open           Open a proof at specific positions
  simulate       Run a full DAS simulation
  help           Show this help
 
Examples:
  frida-das generate-data --size 65536 --out data.bin
  frida-das commit --data data.bin --blowup 8 --folding 4 --remainder 31 --batch 64 --queries 32
  frida-das simulate --data data.bin --nodes 50 --samples 32 --workers 8
`)
}
