// Package ipam provides IP address management utilities.
// The implementation is taken from https://github.com/jsiebens/ionscale/blob/633f29003c72fb4efc31433bb7f37269cbfaa7dc/internal/addr/addr.go
package ipam

import (
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/riyaz-ali/wirefire/internal/util"
	"github.com/rs/zerolog/log"
	"math/big"
	"net"
	"net/netip"
	"tailscale.com/net/tsaddr"
)

var ipv4Range *net.IPNet
var ipv4Count uint64

func init() { ipv4Range, ipv4Count = prepareIP4Range() }

func prepareIP4Range() (*net.IPNet, uint64) {
	cgnatRange := tsaddr.CGNATRange()
	_, ipNet, err := net.ParseCIDR(cgnatRange.String())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse Tailscale CGNAT range")
	}
	return ipNet, cidr.AddressCount(ipNet)
}

// Predicate is a user-defined predicate function used to filter ip addresses
type Predicate func(netip.Addr) (bool, error)

func SelectIP(predicate Predicate) (netip.Addr, netip.Addr, error) {
	ip4, err := selectIP(predicate)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}

	return ip4, tsaddr.Tailscale4To6(ip4), nil
}

func selectIP(predicate Predicate) (netip.Addr, error) {
	var n = util.RandUint64(ipv4Count)

	for {
		stdIP, err := cidr.HostBig(ipv4Range, big.NewInt(int64(n)))
		if err != nil {
			return netip.Addr{}, err
		}

		ip, _ := netip.AddrFromSlice(stdIP)

		if ok, err := validateIP(ip, predicate); err != nil {
			return netip.Addr{}, err
		} else if ok {
			return ip, nil
		}
		n = (n + 1) % ipv4Count
	}
}

func validateIP(ip netip.Addr, p Predicate) (bool, error) {
	if tsaddr.IsTailscaleIP(ip) {
		if p != nil {
			return p(ip)
		} else {
			return true, nil
		}
	}
	return false, nil
}
