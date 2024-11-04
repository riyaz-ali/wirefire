package domain

import (
	"crawshaw.io/sqlite"
	"database/sql"
	"encoding/json"
	"github.com/riyaz-ali/wirefire/internal/database"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"time"
)

// RegistrationRequest represents a node's request to join a tailnet network.
//
// A new request is created when a node first makes the /machine/register request.
// The request is subsequently accessed and modified by the /oidc endpoints.
//
// For more details on authentication and error propagation, see oidc.AuthComplete and coordinator.MachineRegister
type RegistrationRequest struct {
	ID            string                  `db:"id"`            // random text id used to identify requests; exposed in callback endpoint
	NoiseKey      key.MachinePublic       `db:"noise_key"`     // machine's public key used when establishing secure Noise channel over /ts2021
	Data          tailcfg.RegisterRequest `db:"data,json"`     // tailcfg.RegisterRequest object passed to /machine/register
	Authenticated bool                    `db:"authenticated"` // is the request authenticated? becomes true after oidc flow completes successfully
	Error         string                  `db:"error"`         // any error that occurs during authentication flow

	UserID sql.Null[int] `db:"user_id"`
	User   *User         `db:"user,json"` // the user who authenticated the request

	CreatedAt time.Time `db:"created_at"`
}

// CreateRegistrationRequest creates a new registration request for node, identified by its noise key,
// and the given request data passed into /machine/register.
func CreateRegistrationRequest(id string, nk key.MachinePublic, req tailcfg.RegisterRequest) database.I[database.EmptyResponse, RegistrationRequest] {
	return database.I[database.EmptyResponse, RegistrationRequest]{
		QueryStr: "INSERT INTO machine_registration_requests(id, noise_key, data) VALUES (?, ?, ?)",
		ArgSet:   []RegistrationRequest{{ID: id, NoiseKey: nk, Data: req}},

		Bind: func(stmt *sqlite.Stmt, arg RegistrationRequest) error {
			stmt.BindText(1, arg.ID)
			stmt.BindText(2, arg.NoiseKey.String())

			data, err := json.Marshal(arg.Data)
			stmt.BindBytes(3, data)

			return err
		},
	}
}

// RegistrationRequestById returns the RegistrationRequest identified by the given id.
func RegistrationRequestById(id string) database.Q[RegistrationRequest] {
	return database.Q[RegistrationRequest]{
		QueryStr: `
			SELECT r.*, json_object('ID', u.id, 'Subject', u.sub, 'Name', u.name, 'Claims', json(u.claims), 'CreatedAt', u.created_at) AS user
			FROM machine_registration_requests r
			LEFT JOIN users u ON u.id = r.user_id 
				WHERE r.id = ?
		`,
		Bind: func(stmt *sqlite.Stmt) error {
			stmt.BindText(1, id)
			return nil
		},
		Val: func(stmt *sqlite.Stmt) (*RegistrationRequest, error) {
			return database.ScanAs[RegistrationRequest](stmt)
		},
	}
}

// SaveRegistrationRequest saves the updated registration request.
func SaveRegistrationRequest(req *RegistrationRequest) database.I[database.EmptyResponse, *RegistrationRequest] {
	return database.I[database.EmptyResponse, *RegistrationRequest]{
		QueryStr: `UPDATE machine_registration_requests SET authenticated = ?, error = ?, user_id = ? WHERE id = ?`,
		ArgSet:   []*RegistrationRequest{req},
		Bind: func(stmt *sqlite.Stmt, a *RegistrationRequest) error {
			stmt.BindText(4, a.ID)
			stmt.BindBool(1, a.Authenticated)
			stmt.BindText(2, a.Error)

			if a.UserID.Valid {
				stmt.BindInt64(3, int64(a.UserID.V))
			} else {
				stmt.BindNull(3)
			}

			return nil
		},
	}
}
