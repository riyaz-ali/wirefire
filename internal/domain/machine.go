package domain

import (
	"crawshaw.io/sqlite"
	"encoding/json"
	"fmt"
	"github.com/riyaz-ali/tacl"
	"github.com/riyaz-ali/wirefire/internal/database"
	"net/netip"
	"strconv"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
	"time"
)

// Machine represents an individual node in the Tailnet. A machine belongs to a User,
// and it's lifecycle is tied to the Tailnet's and the User's lifecycle.
//
// A node is assigned an IP when it is created. Node is created using information present in tailcfg.RegisterRequest
// passed to the /machine/register endpoint, and is updated by the node using tailcfg.MapRequest passed into /machine/map endpoint.
//
// For node creation, refer to oidc.AuthComplete handler.
type Machine struct {
	ID        int               `db:"id"`             // auto-generated unique machine identifier
	Name      string            `db:"name"`           // machine's hostname
	NameIdx   int               `db:"name_idx"`       // arbiter used as suffix to guarantee unique hostname within a given tailnet
	NoiseKey  key.MachinePublic `db:"noise_key"`      // machine's public key used when establishing secure Noise channel over /ts2021
	NodeKey   key.NodePublic    `db:"node_key"`       // key used for wireguard tunnel and for communication over DERP
	DiscoKey  key.DiscoPublic   `db:"disco_key"`      // key used for peer-to-peer path discovery
	Ephemeral bool              `db:"ephemeral"`      // is the device ephemeral?
	HostInfo  *tailcfg.Hostinfo `db:"host_info,json"` // serialized tailcfg.HostInfo object from either the first registration request or subsequent map requests
	Endpoints []netip.AddrPort  `db:"endpoints,json"` // machine's magicsock UDP ip:port endpoints (can be public and / or private addresses)
	IPv4      netip.Addr        `db:"ipv4"`           // assigned IPv4 address for this node

	CreatedAt time.Time  `db:"created_at"`
	ExpiresAt time.Time  `db:"expires_at"`
	LastSeen  *time.Time `db:"last_seen"`

	TailnetID int      `db:"tailnet_id"`
	Tailnet   *Tailnet `db:"tailnet,json"` // the Tailnet this node is part of

	UserID int   `db:"user_id"`
	Owner  *User `db:"user,json"` // user this node belongs to; renamed to prevent conflict with User()

	// Role of the user for whom this object was fetched.
	//
	// This field isn't stored in the tailnet's table and is only added by the ListMachines
	// query to when JOINed with tailnet_members table for a given user.
	Role string `db:"role"`
}

func (m *Machine) HostName() string           { return m.CompleteName() }
func (m *Machine) Tags() []string             { return nil }
func (m *Machine) User() tacl.User            { return m.Owner }
func (m *Machine) AllowedIPs() []netip.Prefix { return nil }
func (m *Machine) IP() (v4, v6 netip.Addr)    { return m.IPv4, tsaddr.Tailscale4To6(m.IPv4) }

// IsExpired returns true if the machine has expired.
func (m *Machine) IsExpired() bool { return !m.ExpiresAt.IsZero() && m.ExpiresAt.Before(time.Now()) }

// CompleteName returns the machine's name with optional name_idx suffix applied.
func (m *Machine) CompleteName() string {
	if m.NameIdx != 0 {
		return fmt.Sprintf("%s-%d", m.Name, m.NameIdx)
	}

	return m.Name
}

func (m *Machine) AsNode() *tailcfg.Node {
	var node = &tailcfg.Node{
		ID:       tailcfg.NodeID(m.ID),
		StableID: tailcfg.StableNodeID(strconv.FormatUint(uint64(m.ID), 10)),

		// using a default wirefire.net suffix here; replace with DnsConfig.MagicDnsSuffix
		Name: fmt.Sprintf("%s.%s.%s.", m.CompleteName(), dnsname.SanitizeHostname(m.Tailnet.Name), "wirefire.net"),
		User: tailcfg.UserID(m.UserID),

		Key:      m.NodeKey,
		Machine:  m.NoiseKey,
		DiscoKey: m.DiscoKey,

		Hostinfo: m.HostInfo.View(),

		Created:  m.CreatedAt,
		LastSeen: m.LastSeen,

		CapMap:       make(map[tailcfg.NodeCapability][]tailcfg.RawMessage),
		Capabilities: make([]tailcfg.NodeCapability, 0),
	}

	if !m.ExpiresAt.IsZero() {
		node.KeyExpiry = m.ExpiresAt.UTC()
		node.Expired = m.ExpiresAt.Before(time.Now())
	}

	node.DERP = "127.3.3.40:0" // see: tailcfg.Node.DERP for details on the format
	if ni := m.HostInfo.NetInfo; ni != nil {
		node.DERP = fmt.Sprintf("127.3.3.40:%d", ni.PreferredDERP)
	}

	// TODO(@riyaz): also take into account approved routes for machine
	var addrs, allowedIps []netip.Prefix

	if v4, v6 := m.IP(); v4.IsValid() {
		p4, _ := v4.Prefix(32)
		p6, _ := v6.Prefix(128)

		addrs = append(addrs, p4, p6)
		allowedIps = append(allowedIps, p4, p6)
	}

	node.Addresses = addrs
	node.AllowedIPs = allowedIps
	node.Endpoints = m.Endpoints

	// TODO(@riyaz): add support for tags
	node.MachineAuthorized = true

	return node
}

// SaveMachine upsert the machine into the database. If an existing machine with the same (noise_key, node_key) pair
// is found, the record is updated.
//
// Only select few fields are update-able! Most notably, the noise_key and tailnet membership cannot be changed after creation.
func SaveMachine(m *Machine) database.I[Machine, *Machine] {
	return database.I[Machine, *Machine]{
		QueryStr: `
			INSERT INTO machines (name, name_idx, noise_key, node_key, disco_key, ephemeral, host_info, endpoints, ipv4, expires_at, last_seen, tailnet_id, user_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (noise_key) 
				DO UPDATE 
				SET name       = EXCLUDED.name, 
					name_idx   = EXCLUDED.name_idx, 
					node_key   = EXCLUDED.node_key, 
					disco_key  = EXCLUDED.disco_key,
					host_info  = EXCLUDED.host_info,
					endpoints  = EXCLUDED.endpoints,
					expires_at = EXCLUDED.expires_at,
					last_seen  = EXCLUDED.last_seen
			RETURNING 
			    id, 
				name, 
				name_idx, 
				noise_key, 
				node_key, 
				disco_key, 
				ephemeral, 
				host_info, 
			    endpoints,
				ipv4, 
			    created_at
				expires_at,
			    last_seen,
				(SELECT json_object('ID', id, 'Subject', sub, 'Name', name, 'Claims', json(claims), 'CreatedAt', created_at) FROM users WHERE users.id = machines.user_id) AS user,
				(SELECT json_object('ID', id, 'Name', name, 'Acl', acl) FROM tailnets WHERE tailnets.id = machines.tailnet_id) AS tailnet
		`,

		ArgSet: []*Machine{m},

		Bind: func(stmt *sqlite.Stmt, m *Machine) error {
			stmt.BindText(1, m.Name)
			stmt.BindInt64(2, int64(m.NameIdx))
			stmt.BindText(3, m.NoiseKey.String())
			stmt.BindText(4, m.NodeKey.String())
			stmt.BindText(5, m.DiscoKey.String())
			stmt.BindBool(6, m.Ephemeral)

			hostInfo, err := json.Marshal(m.HostInfo)
			if err != nil {
				return err
			}
			stmt.BindBytes(7, hostInfo)

			endpoints, err := json.Marshal(m.Endpoints)
			if err != nil {
				return err
			}
			stmt.BindBytes(8, endpoints)

			stmt.BindText(9, m.IPv4.String())
			stmt.BindText(10, m.ExpiresAt.Format(time.RFC3339))
			if m.LastSeen != nil && !m.LastSeen.IsZero() {
				stmt.BindText(11, m.LastSeen.Format(time.RFC3339))
			} else {
				stmt.BindNull(11)
			}

			stmt.BindInt64(12, int64(m.Tailnet.ID))
			stmt.BindInt64(13, int64(m.Owner.ID))

			return nil
		},

		Val: func(stmt *sqlite.Stmt) (*Machine, error) {
			return database.ScanAs[Machine](stmt)
		},
	}
}

// GetMachineByKey returns the machine identified by its noise key.
func GetMachineByKey(k key.MachinePublic) database.Q[Machine] {
	return database.Q[Machine]{
		QueryStr: `
			SELECT m.*, 
			       json_object('ID', t.id, 'Name', t.name, 'Acl', t.acl, 'CreatedAt', t.created_at, 'UpdatedAt', t.updated_at) AS tailnet, 
			       json_object('ID', u.id, 'Subject', u.sub, 'Name', u.name, 'Claims', json(u.claims), 'CreatedAt', u.created_at) AS user 
			FROM machines m
				INNER JOIN tailnets t ON m.tailnet_id = t.id
				INNER JOIN users    u ON m.user_id    = u.id
			WHERE noise_key = ?
		`,
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindText(1, k.String())
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*Machine, error) {
			return database.ScanAs[Machine](stmt)
		},
	}
}

// ExpireNode update the node's ExpireAt timestamp to the given expiry time.
func ExpireNode(m *Machine, expiry time.Time) database.I[database.EmptyResponse, key.MachinePublic] {
	return database.I[database.EmptyResponse, key.MachinePublic]{
		QueryStr: "UPDATE machines SET expires_at = ? WHERE noise_key = ?",
		ArgSet:   []key.MachinePublic{m.NoiseKey},
		Bind: func(stmt *sqlite.Stmt, key key.MachinePublic) error {
			stmt.BindText(1, expiry.Format(time.RFC3339))
			stmt.BindText(2, key.String())

			return nil
		},
	}
}

// DeleteNode deletes the given machine record from the database.
func DeleteNode(m *Machine) database.I[database.EmptyResponse, key.MachinePublic] {
	return database.I[database.EmptyResponse, key.MachinePublic]{
		QueryStr: "DELETE FROM machines WHERE noise_key = ?",
		ArgSet:   []key.MachinePublic{m.NoiseKey},
		Bind: func(stmt *sqlite.Stmt, key key.MachinePublic) error {
			stmt.BindText(1, key.String())
			return nil
		},
	}
}

// CheckIpInTailnet returns true if the provided ip exists in the given tailnet.
func CheckIpInTailnet(ip netip.Addr, tailnet *Tailnet) database.Q[bool] {
	return database.Q[bool]{
		QueryStr: `SELECT EXISTS (SELECT 1 FROM machines WHERE tailnet_id = $1 AND ipv4 = $2)`,
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindInt64(1, int64(tailnet.ID))
			stmt.BindText(2, ip.String())
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*bool, error) {
			exists := stmt.ColumnInt(0) == 1
			return &exists, nil
		},
	}
}

// GetNextNameIndex returns the next index number for use as arbiter to distinguish between machine's with same hostname.
func GetNextNameIndex(tailnet *Tailnet, name string) database.Q[int] {
	return database.Q[int]{
		QueryStr: "SELECT name_idx FROM machines WHERE name = $1 AND tailnet_id = $2 ORDER BY name_idx DESC",
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindText(1, name)
			stmt.BindInt64(2, int64(tailnet.ID))

			return nil
		},

		Val: func(stmt *sqlite.Stmt) (*int, error) {
			// the query returns the "current" index value; so we increment by 1 to get the "next"
			idx := stmt.ColumnInt(0) + 1

			return &idx, nil
		},
	}
}
