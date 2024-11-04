package domain

import (
	"bytes"
	"crawshaw.io/sqlite"
	"encoding/json"
	"github.com/riyaz-ali/wirefire/internal/database"
	"time"
)

// UserClaims is a set of standard oidc claims returned by the
// provider during login step in the oidc token.
type UserClaims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email,omitempty"`
	Picture string `json:"picture,omitempty"`
}

// User represents an individual user on the system.
//
// A user can be part of 0 or more tailnets and own machines that
// participate in the tailnet network.
type User struct {
	ID      int        `db:"id"`          // auto-generated, unique id of the user
	Subject string     `db:"sub"`         // subject claim extracted from the oidc token
	Name    string     `db:"name"`        // name claim extracted from the oidc token
	Claims  UserClaims `db:"claims,json"` // standard user claims present in the oidc token

	CreatedAt time.Time `db:"created_at"`
}

// FindOrCreateUser returns a user or create a new one based the provided claims.
//
// UserClaims.Subject is used to uniquely identify a user in the system.
func FindOrCreateUser(claims UserClaims) database.Q[User] {
	return database.Q[User]{
		QueryStr: "INSERT INTO users (claims) VALUES ($1) ON CONFLICT (sub) DO UPDATE SET claims = EXCLUDED.claims RETURNING *",
		Bind: func(stmt *sqlite.Stmt) (err error) {
			var buf bytes.Buffer
			if err = json.NewEncoder(&buf).Encode(claims); err != nil {
				return err
			}

			stmt.BindBytes(1, buf.Bytes())
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*User, error) {
			return database.ScanAs[User](stmt)
		},
	}
}

// UserBySubject returns a user account for the given subject.
func UserBySubject(subject string) database.Q[User] {
	return database.Q[User]{
		QueryStr: "SELECT * FROM users WHERE sub = $1",
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindText(1, subject)
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*User, error) {
			return database.ScanAs[User](stmt)
		},
	}
}

// CheckMembership returns true is the user is part of the given tailnet
func CheckMembership(u *User, tailnet int64) database.Q[bool] {
	return database.Q[bool]{
		QueryStr: "SELECT EXISTS (SELECT 1 FROM tailnet_members WHERE user_id = $1 AND tailnet_id = $2)",
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindInt64(1, int64(u.ID))
			stmt.BindInt64(2, tailnet)

			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*bool, error) {
			exists := stmt.ColumnInt(0) == 1
			return &exists, nil
		},
	}
}
