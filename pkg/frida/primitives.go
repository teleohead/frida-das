package frida

import (
	"github.com/consensys/gnark-crypto/field/goldilocks"
)

const (
	// BytesPerElement is the size of a Goldilocks field element.
	BytesPerElement = 8

	// HashBytes is the SHA-256 output size.
	HashBytes = 32

	// GoldilocksPrime is the 2^64 - 2^32 + 1
	GoldilocksPrime = 0xFFFFFFFF00000001
)

// Scalar is a finite-field element in the Goldilocks field.
type Scalar = goldilocks.Element

// Hash is a 32-byte digest (SHA-256).
type Hash = [32]byte

type Commitment struct {
	// Roots[i] is Merkle root of oracle layer i.
	Roots []Hash

	// FinalLayer = G_r
	FinalLayer []Scalar

	// QueryProofs contains L (Params.NumQueries) self-checked proofs.
	// QueryProofs[i] authenticates the i-th Fiat-Shamir query.
	QueryProofs []Proof

	// QueryPositions[i] is the position sampled at i-th query.
	QueryPositions []int
}

// ByteSize calculates the serialized size of a Commitment.
func (c *Commitment) ByteSize() int {
	size := len(c.Roots) * HashBytes
	size += len(c.FinalLayer) * BytesPerElement
	size += len(c.QueryPositions) * 4
	for i := range c.QueryProofs {
		size += c.QueryProofs[i].ByteSize()
	}
	return size
}

// MerklePath is the authentication path of a single leaf.
type MerklePath struct {
	LeafValue []byte
	Siblings  []Hash
	Index     int
	NumLeaves int
}

// LayerProof holds the Merkle paths for a single FRI oracle layer.
type LayerProof struct {
	Paths []MerklePath
}

// Proof combines Merkle paths across all oracle layers into a single query.
// It is both used in Commitment.QueryProofs and as the return value of Open().
type Proof struct {
	Layers []LayerProof
}

// ByteSize calculates the serialized size of a Proof.
func (proof *Proof) ByteSize() int {
	size := 0
	// 4 bytes (index) + 4 bytes (NumLeaves)
	const pathOverhead = 8
	for _, layer := range proof.Layers {
		for _, path := range layer.Paths {
			cryptoSize := len(path.LeafValue) + len(path.Siblings)*HashBytes
			size += cryptoSize + pathOverhead
		}
	}
	return size
}
