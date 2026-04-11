package main

import (
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
