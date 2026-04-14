package frida

import (
	"encoding/binary"
	"fmt"
)

// serializeSymbol extracts B scalars at domain point s from the interleaved slab and converts to bytes.
func serializeSymbol(slab []Scalar, s int, batchSize int) []byte {
	buf := make([]byte, batchSize*BytesPerElement)
	for j := 0; j < batchSize; j++ {
		val := slab[s*batchSize+j].Uint64()
		binary.LittleEndian.PutUint64(buf[j*BytesPerElement:], val)
	}
	return buf
}

// scalarToBytes converts a single scalar to 8-byte data (in little-endian representation).
func scalarToBytes(s *Scalar) []byte {
	buf := make([]byte, BytesPerElement)
	binary.LittleEndian.PutUint64(buf, s.Uint64())
	return buf
}

// BytesToScalars converts bytes to an array of scalars.
func bytesToScalars(data []byte) ([]Scalar, error) {
	n := (len(data) + BytesPerElement - 1) / BytesPerElement

	scalars := make([]Scalar, n)
	for i := 0; i < n; i++ {
		// Take 8 bytes at a time and convert to Scalar
		end := i*BytesPerElement + BytesPerElement
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i*BytesPerElement : end]

		// Pad the chunk with zeros if it's less than 8 bytes
		var paddedChunk [BytesPerElement]byte
		copy(paddedChunk[:], chunk)

		value := binary.LittleEndian.Uint64(paddedChunk[:])

		if value >= uint64(GoldilocksPrime) {
			return nil, fmt.Errorf("invalid data: value %d exceeds Goldilocks prime", value)
		}

		scalars[i].SetUint64(value)
	}

	return scalars, nil
}
