package coordinator

import (
	"context"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/wirefire/internal/util"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// MachineRegister implements handler for the /machine/register endpoint served over Noise channel.
//
// The /machine/register endpoint is the first endpoint that the node talks to start the authentication process.
// This endpoint is used by the node to register its Noise public-key and Node public-key and kick-off a user authentication process.
//
// Upon successful authentication, the machine registration request is marked as successful and the node is added to the selected tailnet.
func MachineRegister(peer key.MachinePublic) util.HandlerFunc[tailcfg.RegisterRequest, tailcfg.RegisterResponse] {
	return func(ctx context.Context, payload tailcfg.RegisterRequest) (_ *tailcfg.RegisterResponse, err error) {
		return nil, errors.New("not implemented")
	}
}
