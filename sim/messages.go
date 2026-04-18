package sim

import (
	"time"

	"github.com/teleohead/frida-das/pkg/frida"
)

// SampleRequest is sent from a light node to a network.
type SampleRequest struct {
	NodeID   int
	Position int
	Response chan<- SampleResponse // dedicated channel per request — no contention
}

// SampleResponse is the network's reply to a SampleRequest.
type SampleResponse struct {
	Position    int
	Evaluations []frida.Scalar // B field elements
	Proof       frida.FriProof
	Err         error
}

// NodeResult is the final report from a light node to the simulator.
type NodeResult struct {
	NodeID           int
	SampledPositions []int
	AcceptedCount    int
	RejectedCount    int
	TotalVerifyNs    time.Duration
	Err              error
}
