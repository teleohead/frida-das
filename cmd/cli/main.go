package main

import (
	"fmt"
	"log"

	"github.com/teleohead/frida-das/pkg/frida"
	"github.com/teleohead/frida-das/sim"
)

func main() {
	params := frida.FriParams{
		BlowupFactor:       2,
		FoldingFactor:      2,
		MaxRemainderDegree: 1,
		NumQueries:         8,
		BatchSize:          4,
	}

	data := make([]byte, 4*1024)
	for i := range data {
		data[i] = byte(i & 0x7F)
	}

	cfg := sim.SimConfig{
		Params:         params,
		Data:           data,
		NumNodes:       50,
		SamplesPerNode: 20,
	}

	fmt.Printf("Running simulation (%d nodes × %d samples, 4 KiB block)\n",
		cfg.NumNodes, cfg.SamplesPerNode)
	result, err := sim.RunSimulation(cfg)
	if err != nil {
		log.Fatalf("simulation failed: %v", err)
	}

	fmt.Println(result)

	const outFile = "sim_result.json"
	if err := result.ExportJSON(outFile); err != nil {
		log.Printf("warning: could not write JSON: %v", err)
	} else {
		fmt.Printf("Wrote %s\n", outFile)
	}
}
