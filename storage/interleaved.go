package storage

import (
	"fmt"

	"github.com/teleohead/frida-das/pkg/frida"
)

type InterleavedSlab struct {
	Data []frida.Scalar
	Size int
}

func (s *InterleavedSlab) GetBatch(index int) ([]frida.Scalar, error) {
	if index < 0 {
		return nil, fmt.Errorf("batch index %d must be non-negative", index)
	}

	start := index * frida.BatchSize
	end := start + frida.BatchSize

	if end > s.Size {
		return nil, fmt.Errorf("batch index %d out of bounds for slab size %d", index, s.Size)
	}

	return s.Data[start:end], nil
}
