package frida

import (
	"crypto/sha256"
)

type MerkleTree struct {
	Root   Hash
	Leaves [][]byte
	Nodes  []Hash
}

// Builds a Merkle tree from the given leaves and returns the tree structure.
func buildMerkleTree(leaves [][]byte) MerkleTree {

	n := len(leaves)
	nodes := make([]Hash, 2*n)

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

	return MerkleTree{
		Root:   nodes[1],
		Leaves: leaves,
		Nodes:  nodes,
	}
}

// Creates a merkle proof for a given leaf index in the tree.
func getMerkleProof(tree MerkleTree, index int) MerklePath {
	proof := make([]Hash, 0, 32)
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

	path := MerklePath{
		LeafValue: tree.Leaves[index],
		Siblings:  proof,
		Index:     index,
		NumLeaves: n,
	}
	return path
}

// Verifies a Merkle proof.
func VerifyMerkleProof(root Hash, path MerklePath) bool {
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
