package sim

import (
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

func (net *Network) Start() {
	for i := 0; i < net.NumWorkers; i++ {
		net.wg.Add(1)
		go net.worker()
	}
}

func (net *Network) Wait() {
	net.wg.Wait()
}

func (net *Network) worker() {
	defer net.wg.Done()
	for req := range net.RequestChan {
		resp := net.handleRequest(req)
		req.Response <- resp
	}
}

func (net *Network) handleRequest(req SampleRequest) SampleResponse {
	return net.DataProvider.ProvideResponse(net.Prover, req.Position)
}
