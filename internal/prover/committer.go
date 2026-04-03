package prover
import (
	"crypto/sha256"
	"encoding/binary"

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
		var combined []byte
		combined = append(combined, left[:]...)
		combined = append(combined, right[:]...)

		nodes[i] = sha256.Sum256(combined)
	}

	return frida.MerkleTree{
		Root: nodes[1],
		Leaves: leaves,
		Nodes: nodes,
	}
}

type MerklePath struct {
	LeafValue []byte
	Siblings  []frida.Hash
	Index     int
	NumLeaves int
}

// Creates a merkle proof for a given leaf index in the tree.
func GetMerkleProof(tree frida.MerkleTree, index int) frida.MerklePath {
	proof := []frida.Hash{}
	n := len(tree.Leaves)
	
	pos := n + index
	for pos > 1 {
		sibling := 0
		if pos % 2 == 0 {
			sibling = pos + 1
		} else {
			sibling = pos - 1
		}
		proof = append(proof, tree.Nodes[sibling])

		pos /= 2
	}

	path := frida.MerklePath{
		LeafValue: tree.Leaves[index],
		Siblings: proof,
		Index: index,
		NumLeaves: n,
	}
	return path
}

// Verifies a Merkle proof.
func VerifyMerkleProof(root frida.Hash, path frida.MerklePath) bool {
	hash := sha256.Sum256(path.LeafValue)
	pos := path.NumLeaves + path.Index
	for _, sibling := range path.Siblings {
		var combined []byte
		if pos % 2 == 0 {
			combined = append(combined, hash[:]...)
			combined = append(combined, sibling[:]...)
		} else {
			combined = append(combined, sibling[:]...)
			combined = append(combined, hash[:]...)
		}

		hash = sha256.Sum256(combined)
		pos /= 2
	}
	return hash == root
}

// Converts bytes to Scalar
func BytesToScalars(data []byte) []frida.Scalar {
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
		for len(chunk) < 8 {
			chunk = append(chunk, 0)
		}

		value := binary.LittleEndian.Uint64(chunk)
		scalars[i].SetUint64(value)
	}

	return scalars
}