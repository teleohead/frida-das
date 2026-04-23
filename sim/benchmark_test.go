package sim

import (
	"fmt"
	"testing"

	"github.com/teleohead/frida-das/pkg/frida"
)

func makeTestData(sizeBytes int) []byte {
	data := make([]byte, sizeBytes)
	for i := range data {
		data[i] = byte(i & 0x7F)
	}
	return data
}

type benchCase struct {
	name     string
	params   frida.Params
	dataSize int
	eval     frida.PolyEvaluator
	folder   frida.Folder
}

var benchCases = []benchCase{
	{
		name: "256B/baseline/B1/RHO2/F2",
		params: frida.Params{
			BlowupFactor:       2,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         4,
			BatchSize:          1,
		},
		dataSize: 256,
		eval:     frida.NTTEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "1KB/baseline/B2/RHO2/F2",
		params: frida.Params{
			BlowupFactor:       2,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         8,
			BatchSize:          2,
		},
		dataSize: 1 * 1024,
		eval:     frida.BaselineEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "4KB/baseline/B4/RHO2/F2",
		params: frida.Params{
			BlowupFactor:       2,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         8,
			BatchSize:          4,
		},
		dataSize: 4 * 1024,
		eval:     frida.BaselineEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "16KB/baseline/B8/RHO4/F2",
		params: frida.Params{
			BlowupFactor:       4,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         16,
			BatchSize:          8,
		},
		dataSize: 16 * 1024,
		eval:     frida.BaselineEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "64KB/baseline/B16/RHO4/F4",
		params: frida.Params{
			BlowupFactor:       4,
			FoldingFactor:      4,
			MaxRemainderDegree: 1,
			NumQueries:         32,
			BatchSize:          16,
		},
		dataSize: 64 * 1024,
		eval:     frida.BaselineEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},

	{
		name: "256B/ntt/B1/RHO2/F2",
		params: frida.Params{
			BlowupFactor:       2,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         4,
			BatchSize:          1,
		},
		dataSize: 256,
		eval:     frida.NTTEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "1KB/ntt/B2/RHO2/F2",
		params: frida.Params{
			BlowupFactor:       2,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         8,
			BatchSize:          2,
		},
		dataSize: 1 * 1024,
		eval:     frida.NTTEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "4KB/ntt/B4/RHO2/F2",
		params: frida.Params{
			BlowupFactor:       2,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         8,
			BatchSize:          4,
		},
		dataSize: 4 * 1024,
		eval:     frida.NTTEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "16KB/ntt/B8/RHO4/F2",
		params: frida.Params{
			BlowupFactor:       4,
			FoldingFactor:      2,
			MaxRemainderDegree: 1,
			NumQueries:         16,
			BatchSize:          8,
		},
		dataSize: 16 * 1024,
		eval:     frida.NTTEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
	{
		name: "64KB/ntt/B16/RHO4/F4",
		params: frida.Params{
			BlowupFactor:       4,
			FoldingFactor:      4,
			MaxRemainderDegree: 1,
			NumQueries:         32,
			BatchSize:          16,
		},
		dataSize: 64 * 1024,
		eval:     frida.NTTEvaluator{},
		folder:   frida.ParallelBatchFolder{},
	},
}

// commit and prove process
func BenchmarkCommit(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			data := makeTestData(tc.dataSize)
			b.SetBytes(int64(tc.dataSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := (tc.params).CommitAndProve(data, tc.eval, tc.folder)
				if err != nil {
					b.Fatalf("CommitAndProve: %v", err)
				}
			}
		})
	}
}

// open process
func BenchmarkOpen(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			data := makeTestData(tc.dataSize)
			_, prover, err := (tc.params).CommitAndProve(data, tc.eval, tc.folder)
			if err != nil {
				b.Fatalf("setup: %v", err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pos := i % prover.DomainSize
				if _, err := prover.Open([]int{pos}); err != nil {
					b.Fatalf("Open: %v", err)
				}
			}
		})
	}
}

func BenchmarkNewVerifier(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			data := makeTestData(tc.dataSize)
			comm, _, err := (tc.params).CommitAndProve(data, tc.eval, tc.folder)
			if err != nil {
				b.Fatalf("setup: %v", err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := frida.NewVerifier(tc.params, comm); err != nil {
					b.Fatalf("NewVerifier: %v", err)
				}
			}
		})
	}
}

func BenchmarkVerifyCommitmentProofs(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			data := makeTestData(tc.dataSize)
			comm, _, err := (tc.params).CommitAndProve(data, tc.eval, tc.folder)
			if err != nil {
				b.Fatalf("setup: %v", err)
			}
			v, err := frida.NewVerifier(tc.params, comm)
			if err != nil {
				b.Fatalf("NewVerifier: %v", err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := v.Verify(); err != nil {
					b.Fatalf("Verify: %v", err)
				}
			}
		})
	}
}

func BenchmarkVerifySample(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			data := makeTestData(tc.dataSize)
			comm, prover, err := (tc.params).CommitAndProve(data, tc.eval, tc.folder)
			if err != nil {
				b.Fatalf("setup: %v", err)
			}
			v, err := frida.NewVerifier(tc.params, comm)
			if err != nil {
				b.Fatalf("NewVerifier: %v", err)
			}
			hp := NewHonestProvider()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pos := i % prover.DomainSize
				resp := hp.ProvideResponse(prover, pos)
				if err := v.VerifySample(pos, &resp.Proof, resp.Evaluations); err != nil {
					b.Fatalf("VerifySample pos %d: %v", pos, err)
				}
			}
		})
	}
}

func BenchmarkProofSize(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			data := makeTestData(tc.dataSize)
			_, prover, err := (tc.params).CommitAndProve(data, tc.eval, tc.folder)
			if err != nil {
				b.Fatalf("setup: %v", err)
			}
			proof, err := prover.Open([]int{0})
			if err != nil {
				b.Fatalf("Open: %v", err)
			}
			b.ReportMetric(float64(proof.ByteSize()), "bytes/proof")
			b.ReportMetric(float64(prover.DomainSize), "domain_size")
			b.ReportMetric(float64(len(proof.Layers)), "layers")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pos := i % prover.DomainSize
				if _, err := prover.Open([]int{pos}); err != nil {
					b.Fatalf("Open: %v", err)
				}
			}
		})
	}
}

func BenchmarkSimulation(b *testing.B) {
	scenarios := []struct {
		numNodes       int
		samplesPerNode int
	}{
		{numNodes: 10, samplesPerNode: 10},
		{numNodes: 50, samplesPerNode: 20},
		{numNodes: 100, samplesPerNode: 30},
	}

	params := frida.Params{
		BlowupFactor:       2,
		FoldingFactor:      2,
		MaxRemainderDegree: 1,
		NumQueries:         8,
		BatchSize:          4,
	}
	data := makeTestData(4 * 1024)

	for _, sc := range scenarios {
		name := fmt.Sprintf("%dN_%dS", sc.numNodes, sc.samplesPerNode)
		b.Run(name, func(b *testing.B) {
			cfg := SimConfig{
				Params:         params,
				Eval:           frida.NTTEvaluator{},
				Data:           data,
				NumNodes:       sc.numNodes,
				SamplesPerNode: sc.samplesPerNode,
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := RunSimulation(cfg)
				if err != nil {
					b.Fatalf("RunSimulation: %v", err)
				}
				b.ReportMetric(result.Throughput, "sps")
			}
		})
	}
}

func BenchmarkFaultDetection(b *testing.B) {
	params := frida.Params{
		BlowupFactor:       2,
		FoldingFactor:      2,
		MaxRemainderDegree: 1,
		NumQueries:         8,
		BatchSize:          4,
	}
	data := makeTestData(4 * 1024)

	comm, prover, err := (params).CommitAndProve(data, frida.NTTEvaluator{}, frida.ParallelBatchFolder{})
	if err != nil {
		b.Fatalf("setup: %v", err)
	}
	v, err := frida.NewVerifier(params, comm)
	if err != nil {
		b.Fatalf("NewVerifier: %v", err)
	}

	corruptPos := make([]int, prover.DomainSize/2)
	for i := range corruptPos {
		corruptPos[i] = i * 2
	}
	mp := NewMaliciousProvider(corruptPos)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pos := i % prover.DomainSize
		resp := mp.ProvideResponse(prover, pos)
		if resp.Err != nil {
			continue
		}
		_ = v.VerifySample(pos, &resp.Proof, resp.Evaluations)
	}
}
