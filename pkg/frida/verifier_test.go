package frida

import (
	"testing"
)

var (
	testParams = Params{
		BlowupFactor:       2,
		FoldingFactor:      2,
		MaxRemainderDegree: 1,
		NumQueries:         4,
		BatchSize:          2,
	}
	testBlock = func() []byte {
		b := make([]byte, 128)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return b
	}()
)

func mustBuild(t *testing.T) (*Commitment, *ProverState) {
	t.Helper()
	comm, prover, err := testParams.CommitAndProveWith(testBlock, BaselineEvaluator{})
	if err != nil {
		t.Fatalf("CommitAndProve: %v", err)
	}
	return comm, prover
}

func TestNewVerifier_DomainSize(t *testing.T) {
	comm, prover := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v.DomainSize != prover.DomainSize {
		t.Errorf("DomainSize: got %d, want %d", v.DomainSize, prover.DomainSize)
	}
}

func TestNewVerifier_ChallengeCount(t *testing.T) {
	comm, _ := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	want := len(comm.Roots) - 2
	if len(v.Challenges) != want {
		t.Errorf("challenge count: got %d, want %d", len(v.Challenges), want)
	}
}

func TestVerifyCommitmentProofs_HonestCommitment(t *testing.T) {
	comm, _ := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(); err != nil {
		t.Errorf("honest commitment should verify: %v", err)
	}
}

// Swapping a query position to a wrong value should be caught.
func TestVerifyCommitmentProofs_TamperedPosition(t *testing.T) {
	comm, _ := mustBuild(t)
	if len(comm.QueryPositions) == 0 {
		t.Skip("no query positions")
	}
	orig := comm.QueryPositions[0]
	comm.QueryPositions[0] = (orig + 1) % 1024

	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(); err == nil {
		t.Error("tampered position should not verify")
	}
}

// Every domain position should pass verification with honest data.
func TestVerifySample_AllPositions(t *testing.T) {
	comm, prover := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	B := testParams.BatchSize
	for pos := 0; pos < prover.DomainSize; pos++ {
		proof, err := prover.Open([]int{pos})
		if err != nil {
			t.Fatalf("Open pos %d: %v", pos, err)
		}
		evals := make([]Scalar, B)
		copy(evals, prover.BatchOracle[pos*B:(pos+1)*B])

		if err := v.VerifySample(pos, proof, evals); err != nil {
			t.Errorf("pos %d should verify: %v", pos, err)
		}
	}
}

func TestVerifySample_WrongEvals(t *testing.T) {
	comm, prover := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	pos := 0
	proof, err := prover.Open([]int{pos})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	evals := make([]Scalar, testParams.BatchSize)
	for i := range evals {
		evals[i].SetUint64(0xDEADBEEF)
	}
	if err := v.VerifySample(pos, proof, evals); err == nil {
		t.Error("wrong evals should not verify")
	}
}

func TestVerifySample_TamperedLeaf(t *testing.T) {
	comm, prover := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	pos := 0
	proof, err := prover.Open([]int{pos})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	B := testParams.BatchSize
	evals := make([]Scalar, B)
	copy(evals, prover.BatchOracle[pos*B:(pos+1)*B])

	if len(proof.Layers) > 0 && len(proof.Layers[0].Paths) > 0 {
		proof.Layers[0].Paths[0].LeafValue[0] ^= 0xFF
	}

	if err := v.VerifySample(pos, proof, evals); err == nil {
		t.Error("flipped leaf byte should not verify")
	}
}

func TestVerifySample_TamperedSibling(t *testing.T) {
	comm, prover := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	pos := 0
	proof, err := prover.Open([]int{pos})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	B := testParams.BatchSize
	evals := make([]Scalar, B)
	copy(evals, prover.BatchOracle[pos*B:(pos+1)*B])

	tampered := false
	for li := range proof.Layers {
		for pi := range proof.Layers[li].Paths {
			if len(proof.Layers[li].Paths[pi].Siblings) > 0 {
				proof.Layers[li].Paths[pi].Siblings[0][0] ^= 0xFF
				tampered = true
				break
			}
		}
		if tampered {
			break
		}
	}
	if !tampered {
		t.Skip("no siblings to tamper with")
	}

	if err := v.VerifySample(pos, proof, evals); err == nil {
		t.Error("flipped sibling hash should not verify")
	}
}

func TestVerifySample_EmptyProof(t *testing.T) {
	comm, prover := mustBuild(t)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	B := testParams.BatchSize
	evals := make([]Scalar, B)
	copy(evals, prover.BatchOracle[:B])

	if err := v.VerifySample(0, &Proof{}, evals); err == nil {
		t.Error("empty proof should not verify")
	}
}

// BatchSize=1 is an edge case where the batch oracle and G_0 hold the same value.
func TestVerifier_BatchSize1(t *testing.T) {
	params := Params{
		BlowupFactor:       2,
		FoldingFactor:      2,
		MaxRemainderDegree: 1,
		NumQueries:         4,
		BatchSize:          1,
	}
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i + 1)
	}

	comm, prover, err := params.CommitAndProveWith(data, BaselineEvaluator{})
	if err != nil {
		t.Fatalf("CommitAndProve: %v", err)
	}
	v, err := NewVerifier(params, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(); err != nil {
		t.Errorf("commitment proofs should verify: %v", err)
	}

	pos := 0
	proof, err := prover.Open([]int{pos})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	evals := []Scalar{prover.BatchOracle[pos]}
	if err := v.VerifySample(pos, proof, evals); err != nil {
		t.Errorf("B=1 sample should verify: %v", err)
	}
}

func TestVerify_DegreeBoundFailure(t *testing.T) {
	comm, _ := mustBuild(t)
	if len(comm.FinalLayer) <= testParams.MaxRemainderDegree+1 {
		t.Skip("final layer too small to fail degree bound")
	}
	var one Scalar
	one.SetUint64(1)
	// corrupt a single evaluation in the final layer
	comm.FinalLayer[0].Add(&comm.FinalLayer[0], &one)
	v, err := NewVerifier(testParams, comm)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(); err == nil {
		t.Fatal("verifier accepted a final layer that violated the degree bound")
	}
}
