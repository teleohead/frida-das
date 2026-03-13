package storage

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/teleohead/frida-das/pkg/frida"
)

type Manager struct {
	Slab        *InterleavedSlab
	FoldingPool [][]frida.Scalar
}

func NewManager(numElements int) *Manager {
	totalNum := numElements * 2
	block := make([]frida.Scalar, totalNum)
	slab := &InterleavedSlab{
		Data: block[:numElements],
		Size: numElements,
	}

	var foldingPool [][]frida.Scalar
	offset := numElements
	currLayerSize := numElements / 2

	for currLayerSize > 0 {
		foldingPool = append(foldingPool, block[offset:offset+currLayerSize])
		offset += currLayerSize
		currLayerSize = currLayerSize / 2
	}

	return &Manager{
		Slab:        slab,
		FoldingPool: foldingPool,
	}
}

func (m *Manager) LoadFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, frida.BytesPerElement)
	for i := 0; i < len(m.Slab.Data); i++ {
		if _, err := io.ReadFull(f, buf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error when reading at element %d: %w", i, err)
		}
		elems := binary.LittleEndian.Uint64(buf)
		m.Slab.Data[i].SetUint64(elems)
	}
	return nil
}
