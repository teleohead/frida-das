package sim

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/teleohead/frida-das/pkg/frida"
)

type LightNode struct {
	ID          int
	NumSamples  int
	DomainSize  int
	Commitment  *frida.Commitment
	Params      frida.FriParams
	RequestChan chan<- SampleRequest
	ResultChan  chan<- NodeResult
}

func (n *LightNode) Run() {
	positions := n.samplePositions()
	acceptedCount := 0
	rejectedCount := 0

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

		// TODO: Integrate Verifier logic

		if len(response.Proof.Layers) > 0 { // JUST A PLACEHOLDER NOWWWWW !!!
			acceptedCount++
		} else {
			rejectedCount++
		}
	}

	n.ResultChan <- NodeResult{
		NodeID:           n.ID,
		SampledPositions: positions,
		AcceptedCount:    acceptedCount,
		RejectedCount:    rejectedCount,
	}
}

func (n *LightNode) samplePositions() []int {
	positions := make([]int, 0, n.NumSamples)
	taken := make(map[int]bool) // avoid duplications
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
