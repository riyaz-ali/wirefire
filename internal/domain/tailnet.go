package domain

import (
	"crawshaw.io/sqlite"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/tacl"
	"github.com/riyaz-ali/wirefire/internal/database"
	"net/mail"
	"strings"
	"tailscale.com/util/dnsname"
	"time"
)

// ACL wraps tacl.ACL to implement encoding.TextUnmarshaler which uses tacl.Parse
// to parse HuJson formatted policy into ACL struct
type ACL struct{ *tacl.ACL }

func (a *ACL) UnmarshalText(buf []byte) error {
	if a == nil {
		return errors.New("acl: nil pointer")
	}

	acl, err := tacl.Parse(buf)
	if err != nil {
		return err
	}

	a.ACL = acl
	return nil
}

// Tailnet represents an individual tailnet network managed by Wirefire.
type Tailnet struct {
	ID   int    `db:"id"`   // auto-generated unique id of the tailnet
	Name string `db:"name"` // unique name of the tailnet
	Acl  *ACL   `db:"acl"`  // this tailnet's access control policy

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	// Role of the user for whom this object was fetched.
	//
	// This field isn't stored in the tailnet's table and is only added by the ListTailnets
	// query to when JOINed with tailnet_members table for a given user.
	Role string `db:"role"`
}

func SanitizeTailnetName(name string) string {
	name = strings.ToLower(name)

	a, err := mail.ParseAddress(name)
	if err == nil && a.Address == name {
		s := strings.Split(name, "@")
		return strings.Join([]string{dnsname.SanitizeLabel(s[0]), s[1]}, ".")
	}

	labels := strings.Split(name, ".")
	for i, s := range labels {
		labels[i] = dnsname.SanitizeLabel(s)
	}

	return strings.Join(labels, ".")
}

// TailnetById returns the Tailnet identified by the given id.
func TailnetById(id int64) database.Q[Tailnet] {
	return database.Q[Tailnet]{
		QueryStr: "SELECT * FROM tailnets WHERE id = $1",
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindInt64(1, id)
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*Tailnet, error) {
			return database.ScanAs[Tailnet](stmt)
		},
	}
}

// ListTailnets return all tailnets where the given user is a member.
func ListTailnets(u *User) database.Q[Tailnet] {
	return database.Q[Tailnet]{
		QueryStr: `SELECT t.*, m.role AS role FROM tailnets t, tailnet_members m WHERE m.tailnet_id = t.id AND m.user_id = $1`,
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindInt64(1, int64(u.ID))
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*Tailnet, error) {
			return database.ScanAs[Tailnet](stmt)
		},
	}
}

// ListMachines returns a list of all machines that are part of this tailnet
func ListMachines(t *Tailnet) database.Q[Machine] {
	return database.Q[Machine]{
		QueryStr: `
			SELECT m.*, 
			       json_object('ID', t.id, 'Name', t.name, 'Acl', t.acl) AS tailnet, 
			       json_object('ID', u.id, 'Name', u.name) AS user,
			       tailnet_members.role AS role
			FROM machines m
				INNER JOIN tailnets t ON m.tailnet_id = t.id
				INNER JOIN users    u ON m.user_id    = u.id
				INNER JOIN tailnet_members USING (tailnet_id, user_id)
			WHERE m.tailnet_id = ?
		`,
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindInt64(1, int64(t.ID))
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*Machine, error) {
			return database.ScanAs[Machine](stmt)
		},
	}
}
