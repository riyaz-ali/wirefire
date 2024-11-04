package domain

import (
	"crawshaw.io/sqlite"
	"github.com/riyaz-ali/wirefire/internal/database"
	"time"
)

// Tailnet represents an individual tailnet network managed by Wirefire.
type Tailnet struct {
	ID   int    `db:"id"`   // auto-generated unique id of the tailnet
	Name string `db:"name"` // unique name of the tailnet
	Acl  string `db:"acl"`  // this tailnet's access control policy

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	// Role of the user for whom this object was fetched.
	//
	// This field isn't stored in the tailnet's table and is only added by the ListTailnets
	// query to when JOINed with tailnet_members table for a given user.
	Role string `db:"role"`
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
