package coordinator

import (
	"context"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/wirefire/internal/util"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// MachineMap implements handler for the /machine/map endpoint served over the Noise channel.
//
// The /machine/map endpoint is used to the node to update its status and also to start a long-polling
// session to receive status updates from other nodes in the tailnet.
func MachineMap(peer key.MachinePublic) util.StreamingHandlerFunc[tailcfg.MapRequest, tailcfg.MapResponse] {
	return func(ctx context.Context, req tailcfg.MapRequest) (<-chan util.Encodeable[tailcfg.MapResponse], error) {
		return nil, errors.New("not implemented")
	}
}
