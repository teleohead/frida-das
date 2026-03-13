package frida

import (
	"github.com/consensys/gnark-crypto/field/goldilocks"
)

type Scalar = goldilocks.Element

type Commitment struct {
	Roots []Scalar
}

type Proof struct {
	Paths    [][]byte
	Siblings []Scalar
}

type State struct {
	Trees [][]byte
	Data  []Scalar
}
