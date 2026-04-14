package frida

import (
	"crypto/sha256"
	"encoding/binary"
)

// chainHash implements H'(root, hst, i) from Section 3 of the paper.
func chainHash(root Hash, prevHst Hash, roundIndex int) Hash {
	var buf [68]byte
	copy(buf[:32], root[:])
	copy(buf[32:64], prevHst[:])
	binary.BigEndian.PutUint32(buf[64:68], uint32(roundIndex))
	return sha256.Sum256(buf[:])
}

// deriveFieldChallenge derives a field element from a hash state
// This is the hat{H} from Section 3 of the paper.
func deriveFieldChallenge(hst Hash) Scalar {
	h := sha256.Sum256(hst[:])
	val := binary.LittleEndian.Uint64(h[:8]) % GoldilocksPrime
	var s Scalar
	s.SetUint64(val)
	return s
}

// deriveQueryPositions generates L query positions via Fiat-Shamir.
func deriveQueryPositions(finalRoot Hash, hst Hash, domainSize int, numQueries int) []int {
	var seedBuf [64]byte
	copy(seedBuf[:32], finalRoot[:])
	copy(seedBuf[32:], hst[:])

	seed := sha256.Sum256(seedBuf[:])

	positions := make([]int, numQueries)

	for k := 0; k < numQueries; k++ {
		var buf [36]byte
		copy(buf[:32], seed[:])
		binary.BigEndian.PutUint32(buf[32:36], uint32(k))
		h := sha256.Sum256(buf[:])
		val := binary.LittleEndian.Uint64(h[:8])
		positions[k] = int(val % uint64(domainSize))
	}
	return positions
}
