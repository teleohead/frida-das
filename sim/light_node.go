package sim

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/teleohead/frida-das/pkg/frida"
)

type LightNode struct {
	ID          int
	NumSamples  int
	DomainSize  int
	Verifier    *frida.Verifier
	RequestChan chan<- SampleRequest
	ResultChan  chan<- NodeResult
}

func (n *LightNode) Run() {
	positions := n.samplePositions()
	acceptedPositions := make([]int, 0, len(positions))
	acceptedCount := 0
	rejectedCount := 0
	var verifyTime time.Duration

	for _, pos := range positions {
		responseCh := make(chan SampleResponse, 1)
		n.RequestChan <- SampleRequest{
			NodeID:   n.ID,
			Position: pos,
			Response: responseCh,
		}

		response := <-responseCh

		if response.Err != nil {
			rejectedCount++
			continue
		}

		t0 := time.Now()
		err := n.Verifier.VerifySample(pos, &response.Proof, response.Evaluations)
		verifyTime += time.Since(t0)

		if err != nil {
			rejectedCount++
		} else {
			acceptedCount++
			acceptedPositions = append(acceptedPositions, pos)
		}
	}

	n.ResultChan <- NodeResult{
		NodeID:            n.ID,
		SampledPositions:  positions,
		AcceptedPositions: acceptedPositions,
		AcceptedCount:     acceptedCount,
		RejectedCount:     rejectedCount,
		TotalVerifyNs:     verifyTime,
	}
}

func (n *LightNode) samplePositions() []int {
	positions := make([]int, 0, n.NumSamples)
	taken := make(map[int]bool)
	var buf [frida.BytesPerElement]byte
	for len(positions) < n.NumSamples {
		_, _ = rand.Read(buf[:])
		val := binary.LittleEndian.Uint64(buf[:])
		pos := int(val % uint64(n.DomainSize))
		if !taken[pos] {
			taken[pos] = true
			positions = append(positions, pos)
		}
	}
	return positions
}
