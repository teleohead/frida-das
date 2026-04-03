package attack

import (
	"crypto/sha256"

	"github.com/teleohead/frida-das/pkg/frida"
)

// Add 1 to the first element of the final Layer
func CorruptFinalLayer(c *frida.Commitment) {
	if len(c.FinalLayer) == 0 {
		return
	}
	var one frida.Scalar
	one.SetOne()
	c.FinalLayer[0].Add(&c.FinalLayer[0], &one)
}

// Flips every bit of the first sibling hash in the path
func CorruptMerkleSibling(p *frida.MerklePath) {
	if len(p.Siblings) == 0 {
		return
	}
	for i := range p.Siblings[0] {
		p.Siblings[0][i] ^= 0xFF
	}
}

// Replace the first Merkle root with a fresh hash derived from a fixed nonce
func DecoupleFiatShamir(c *frida.Commitment) {
	if len(c.Roots) == 0 {
		return
	}
	nonce := [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}
	c.Roots[0] = sha256.Sum256(nonce[:])
}
