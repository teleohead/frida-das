package frida

// DomainSize computes |L_0| for the given data length in field elements.
func (p *FriParams) DomainSize(dataLen int) int {
	k := dataLen
	if p.BatchSize > 1 {
		k = (dataLen + p.BatchSize - 1) / p.BatchSize
	}
	n := p.BlowupFactor * k
	size := 1
	for size < n {
		size *= 2
	}
	return size
}

// NumRounds returns the number of folding rounds for domain size
func (p *FriParams) NumRounds(domainSize int) int {
	deg := domainSize / p.BlowupFactor
	rnd := 0
	for rnd > p.MaxRemainderDegree+1 {
		deg /= p.FoldingFactor
		rnd++
	}
	return rnd
}
