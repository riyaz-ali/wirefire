package util

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
)

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// ToPtr returns a a pointer to v
func ToPtr[T any](v T) *T { return &v }

// Checksum returns the md5 checksum of the given v when encoded as json
func Checksum[T any](v T) string {
	if marshal, err := json.Marshal(v); err != nil {
		panic(err)
	} else {
		sum := md5.Sum(marshal)
		return hex.EncodeToString(sum[:])
	}
}
