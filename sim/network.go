package sim

import (
	"encoding/binary"
	"sync"

	"github.com/teleohead/frida-das/pkg/frida"
)

type Network struct {
	Prover       *frida.FridaProver
	DataProvider DataProvider

	RequestChan <-chan SampleRequest
	NumWorkers  int

	wg sync.WaitGroup
}

func NewNetwork(p *frida.FridaProver, dp DataProvider, requestChan <-chan SampleRequest, numWorkers int) *Network {
	return &Network{
		Prover:       p,
		DataProvider: dp,
		RequestChan:  requestChan,
		NumWorkers:   numWorkers,
	}
}

func (net *Network) handleRequest(req SampleRequest) SampleResponse {
	return net.DataProvider.ProvideResponse(net.Prover, req.Position)
}
