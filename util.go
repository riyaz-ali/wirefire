package main

import (
	"strings"
	"tailscale.com/types/key"
)

// ParsePrivateKey parses hex-encoded private key into key.MachinePrivate
func ParsePrivateKey(in string) (_ key.MachinePrivate, err error) {
	const prefix = "privkey:"

	if !strings.HasPrefix(in, prefix) {
		in = prefix + in
	}

	var mp key.MachinePrivate
	err = mp.UnmarshalText([]byte(in))

	return mp, err
}
