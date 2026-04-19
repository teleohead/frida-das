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

	// QueryProofs contains L (FriParams.NumQueries) self-checked proofs.
	// QueryProofs[i] authenticates the i-th Fiat-Shamir query.
	QueryProofs []FriProof

	// QueryPositions[i] is the position sampled at i-th query.
	QueryPositions []int
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

// FriProof combines Merkle paths across all oracle layers into a single query.
// It is both used in Commitment.QueryProofs and as the return value of Open().
type FriProof struct {
	Layers []LayerProof
}

type MerkleTree struct {
	Root   Hash
	Leaves [][]byte
	Nodes  []Hash
}
