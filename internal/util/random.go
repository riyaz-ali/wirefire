package util

import (
	"crypto/rand"
	"math/big"
)

// RandUint64 returns a secure-random uint64 value generated using crypto/rand
func RandUint64(n uint64) uint64 { return Must(rand.Int(rand.Reader, big.NewInt(int64(n)))).Uint64() }
