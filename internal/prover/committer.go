package prover

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/teleohead/frida-das/pkg/frida"
)

// Builds a Merkle tree from the given leaves and returns the tree structure.
func BuildMerkleTree(leaves [][]byte) frida.MerkleTree {

	n := len(leaves)
	nodes := make([]frida.Hash, 2*n)

	for i := 0; i < n; i++ {
		// Hash each leaf
		nodes[n+i] = sha256.Sum256(leaves[i])
	}

	for i := n - 1; i > 0; i-- {
		left := nodes[2*i]
		right := nodes[2*i+1]

		// Combine left and right hashes
		var combined [64]byte
		copy(combined[:32], left[:])
		copy(combined[32:], right[:])
		nodes[i] = sha256.Sum256(combined[:])
	}

	return frida.MerkleTree{
		Root:   nodes[1],
		Leaves: leaves,
		Nodes:  nodes,
	}
}

// Creates a merkle proof for a given leaf index in the tree.
func GetMerkleProof(tree frida.MerkleTree, index int) frida.MerklePath {
	proof := make([]frida.Hash, 0, 32)
	n := len(tree.Leaves)

	pos := n + index
	for pos > 1 {
		sibling := 0
		if pos%2 == 0 {
			sibling = pos + 1
		} else {
			sibling = pos - 1
		}
		proof = append(proof, tree.Nodes[sibling])

		pos /= 2
	}

	path := frida.MerklePath{
		LeafValue: tree.Leaves[index],
		Siblings:  proof,
		Index:     index,
		NumLeaves: n,
	}
	return path
}

// Verifies a Merkle proof.
func VerifyMerkleProof(root frida.Hash, path frida.MerklePath) bool {
	hash := sha256.Sum256(path.LeafValue)
	pos := path.NumLeaves + path.Index
	for _, sibling := range path.Siblings {
		var combined [64]byte
		if pos%2 == 0 {
			copy(combined[:32], hash[:])
			copy(combined[32:], sibling[:])
		} else {
			copy(combined[:32], sibling[:])
			copy(combined[32:], hash[:])
		}

		hash = sha256.Sum256(combined[:])
		pos /= 2
	}
	return hash == root
}

// BytesToScalars converts bytes to Scalar's.
func BytesToScalars(data []byte) ([]frida.Scalar, error) {
	n := (len(data) + 7) / 8

	scalars := make([]frida.Scalar, n)
	for i := 0; i < n; i++ {
		// Take 8 bytes at a time and convert to Scalar
		end := i*8 + 8
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i*8 : end]

		// Pad the chunk with zeros if it's less than 8 bytes
		var paddedChunk [8]byte
		copy(paddedChunk[:], chunk)

		value := binary.LittleEndian.Uint64(paddedChunk[:])

		if value >= uint64(0xFFFFFFFF00000001) {
			return nil, fmt.Errorf("invalid data: value %d exceeds Goldilocks prime", value)
		}

		scalars[i].SetUint64(value)
	}

	return scalars, nil
}
