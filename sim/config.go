package sim

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/teleohead/frida-das/pkg/frida"
)

type SimConfig struct {
	Params           frida.Params
	Eval             frida.PolyEvaluator
	Data             []byte
	NumNodes         int
	SamplesPerNode   int
	NetworkWorkers   int     // number of concurrent goroutines, defaults to GOMAXPROCS
	CorruptPositions []int   // explicit positions to corrupt
	CorruptFraction  float64 // fraction of domain to corrupt (0.0–1.0); applied after commit if CorruptPositions is empty
}

type SimResult struct {
	Config      SimConfig    `json:"config"`
	NodeResults []NodeResult `json:"node_results"`

	TotalSampled    int  `json:"total_sampled"`
	TotalAccepted   int  `json:"total_accepted"`
	TotalRejected   int  `json:"total_rejected"`
	Reconstructable bool `json:"reconstructable"`

	CommitTimeNs    time.Duration `json:"commit_time_ns"`
	AvgProofTimeNs  time.Duration `json:"avg_proof_time_ns"`  // time it takes for an Open() call
	AvgVerifyTimeNs time.Duration `json:"avg_verify_time_ns"` // time it takes for an Verify() call

	SingleProofBytes int           `json:"single_proof_bytes"`
	SamplingTimeNs   time.Duration `json:"sampling_time_ns"`
	Throughput       float64       `json:"throughput_sps"` // unit of measurement: samples per second
}

func (r *SimResult) String() string {
	return fmt.Sprintf(
		"========================================\n"+
			"           SIMULATION SUMMARY           \n"+
			"========================================\n"+
			"Nodes:           %d\n"+
			"Samples/Node:    %d\n"+
			"Reconstructable: %v\n"+
			"Total Accepted:  %d\n"+
			"Total Rejected:  %d\n"+
			"Throughput:      %.2f SPS\n"+
			"Commit Time:     %s\n"+
			"Avg Proof Time:  %s\n"+
			"Avg Verify Time: %s\n"+
			"Proof Size:      %d bytes\n"+
			"Total Sim Time:  %s\n"+
			"========================================",
		len(r.NodeResults), r.Config.SamplesPerNode,
		r.Reconstructable,
		r.TotalAccepted, r.TotalRejected,
		r.Throughput,
		r.CommitTimeNs, r.AvgProofTimeNs, r.AvgVerifyTimeNs,
		r.SingleProofBytes, r.SamplingTimeNs,
	)
}

// ExportJSON marshals a SimResult and writes the data to disk.
// The data can be then used for the final report.
func (r *SimResult) ExportJSON(filepath string) error {
	fileData, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	err = os.WriteFile(filepath, fileData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}
