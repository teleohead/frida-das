package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
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
