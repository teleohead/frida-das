package attack_test

import (
	"crypto/sha256"
	"testing"

	"github.com/teleohead/frida-das/internal/attack"
	"github.com/teleohead/frida-das/pkg/frida"
)

// 2 polynomials
var (
	testParams = frida.FriParams{
		BlowupFactor:       2,
		FoldingFactor:      2,
		MaxRemainderDegree: 1,
		NumQueries:         2,
		BatchSize:          2,
	}
	testData = func() []byte {
		b := make([]byte, 64)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return b
	}()
)

func mustCommit(t *testing.T) *frida.Commitment {
	t.Helper()
	comm, _, err := frida.NewBuilder(testParams).CommitAndProve(testData)
	if err != nil {
		t.Fatalf("CommitAndProve: %v", err)
	}
	return comm
}

// This function is used to find the first MerklePath with siblings
func firstPathWithSiblings(comm *frida.Commitment) (path *frida.MerklePath, layerIdx int, ok bool) {
	for qi := range comm.QueryProofs {
		for li := range comm.QueryProofs[qi].Layers {
			for pi := range comm.QueryProofs[qi].Layers[li].Paths {
				p := &comm.QueryProofs[qi].Layers[li].Paths[pi]
				if len(p.Siblings) > 0 {
					return p, li, true
				}
			}
		}
	}
	return nil, 0, false
}

// Unit tests

func TestCorruptFinalLayer(t *testing.T) {
	comm := mustCommit(t)

	orig := comm.FinalLayer[0]
	rest := make([]frida.Scalar, len(comm.FinalLayer)-1)
	copy(rest, comm.FinalLayer[1:])

	attack.CorruptFinalLayer(comm)

	if comm.FinalLayer[0] == orig {
		t.Error("FinalLayer[0] was not changed")
	}
	for i, want := range rest {
		if comm.FinalLayer[i+1] != want {
			t.Errorf("FinalLayer[%d] was unexpectedly modified", i+1)
		}
	}
}

func TestCorruptMerkleSibling(t *testing.T) {
	comm := mustCommit(t)

	path, _, ok := firstPathWithSiblings(comm)
	if !ok {
		t.Skip("no paths with siblings")
	}

	orig := path.Siblings[0]
	attack.CorruptMerkleSibling(path)

	for i, b := range path.Siblings[0] {
		if b != orig[i]^0xFF {
			t.Errorf("Siblings[0][%d]: got %02x, want %02x", i, b, orig[i]^0xFF)
		}
	}
}

func TestDecoupleFiatShamir(t *testing.T) {
	comm := mustCommit(t)

	origRoots := make([]frida.Hash, len(comm.Roots))
	copy(origRoots, comm.Roots)

	attack.DecoupleFiatShamir(comm)

	// Roots[0] should be replaced with SHA-256 of the hardcoded nonce.
	nonce := [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}
	if want := sha256.Sum256(nonce[:]); comm.Roots[0] != want {
		t.Errorf("Roots[0] = %x, want %x", comm.Roots[0], want)
	}
	// The rest of the roots are untouched.
	for i := 1; i < len(comm.Roots); i++ {
		if comm.Roots[i] != origRoots[i] {
			t.Errorf("Roots[%d] changed unexpectedly", i)
		}
	}
}

// No error should be raised if the input is empty.
func TestAttacks_NoPanicOnEmpty(t *testing.T) {
	t.Run("CorruptFinalLayer", func(t *testing.T) {
		attack.CorruptFinalLayer(&frida.Commitment{})
	})
	t.Run("CorruptMerkleSibling", func(t *testing.T) {
		attack.CorruptMerkleSibling(&frida.MerklePath{})
	})
	t.Run("DecoupleFiatShamir", func(t *testing.T) {
		attack.DecoupleFiatShamir(&frida.Commitment{})
	})
}

// Integration tests

func TestMerkleProofsVerify(t *testing.T) {
	comm := mustCommit(t)

	for qi, qp := range comm.QueryProofs {
		for li, layer := range qp.Layers {
			for pi, path := range layer.Paths {
				if !frida.VerifyMerkleProof(comm.Roots[li], path) {
					t.Errorf("query %d layer %d path %d: proof should be valid", qi, li, pi)
				}
			}
		}
	}
}

func TestCorruptMerkleSibling_BreaksProof(t *testing.T) {
	comm := mustCommit(t)

	path, li, ok := firstPathWithSiblings(comm)
	if !ok {
		t.Skip("no paths with siblings")
	}

	root := comm.Roots[li]
	attack.CorruptMerkleSibling(path)

	if frida.VerifyMerkleProof(root, *path) {
		t.Error("corrupted proof should not verify")
	}
}

func TestDecoupleFiatShamir_BreaksProof(t *testing.T) {
	comm := mustCommit(t)

	// Collect paths anchored to Roots[0] before we swap it out.
	var paths []frida.MerklePath
	for qi := range comm.QueryProofs {
		if len(comm.QueryProofs[qi].Layers) > 0 {
			paths = append(paths, comm.QueryProofs[qi].Layers[0].Paths...)
		}
	}

	attack.DecoupleFiatShamir(comm)

	for i, p := range paths {
		if frida.VerifyMerkleProof(comm.Roots[0], p) {
			t.Errorf("path %d: proof should not verify against a fake root", i)
		}
	}
}

// This function tests that the corruption of the final layer leaves the proofs intact
func TestCorruptFinalLayer_LeavesProofsIntact(t *testing.T) {
	comm := mustCommit(t)
	attack.CorruptFinalLayer(comm)

	for qi, qp := range comm.QueryProofs {
		for li, layer := range qp.Layers {
			for pi, path := range layer.Paths {
				if !frida.VerifyMerkleProof(comm.Roots[li], path) {
					t.Errorf("query %d layer %d path %d: proof should still be valid", qi, li, pi)
				}
			}
		}
	}
}
