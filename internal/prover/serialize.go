package prover

import (
	"encoding/binary"
	"fmt"

	"github.com/teleohead/frida-das/pkg/frida"
)

// serializeSymbol extracts B scalars at domain point s from the interleaved slab and converts to bytes.
func serializeSymbol(slab []frida.Scalar, s int, batchSize int) []byte {
	buf := make([]byte, batchSize*frida.BytesPerElement)
	for j := 0; j < batchSize; j++ {
		val := slab[s*batchSize+j].Uint64()
		binary.LittleEndian.PutUint64(buf[j*frida.BytesPerElement:], val)
	}
	return buf
}

// scalarToBytes converts a single scalar to 8-byte data (in little-endian representation).
func scalarToBytes(s *frida.Scalar) []byte {
	buf := make([]byte, frida.BytesPerElement)
	binary.LittleEndian.PutUint64(buf, s.Uint64())
	return buf
}

// BytesToScalars converts bytes to an array of scalars.
func bytesToScalars(data []byte) ([]frida.Scalar, error) {
	n := (len(data) + frida.BytesPerElement - 1) / frida.BytesPerElement

	scalars := make([]frida.Scalar, n)
	for i := 0; i < n; i++ {
		// Take 8 bytes at a time and convert to Scalar
		end := i*frida.BytesPerElement + frida.BytesPerElement
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i*frida.BytesPerElement : end]

		// Pad the chunk with zeros if it's less than 8 bytes
		var paddedChunk [frida.BytesPerElement]byte
		copy(paddedChunk[:], chunk)

		value := binary.LittleEndian.Uint64(paddedChunk[:])

		if value >= uint64(frida.GoldilocksPrime) {
			return nil, fmt.Errorf("invalid data: value %d exceeds Goldilocks prime", value)
		}

		scalars[i].SetUint64(value)
	}

	return scalars, nil
}
