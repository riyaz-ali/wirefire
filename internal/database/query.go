package database

import (
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
)

// EmptyResponse is a placeholder type that can be used Q and I to indicate queries
// that doesn't return any rows.
type EmptyResponse struct{}

// Q represents a sqlite query that returns one or more instances of M when executed
type Q[M any] struct {
	// QueryStr is the sql query used to create a prepared statement
	QueryStr string

	// Bind is used to bind any variables to the given statement
	Bind func(stmt *sqlite.Stmt) error

	// Val is used to extract values from the statement and create a new instance of M
	Val func(stmt *sqlite.Stmt) (*M, error)
}

// FetchMany runs the given query and returns a slice of zero or more instances of M
func FetchMany[M any](conn *sqlite.Conn, query Q[M]) (_ []*M, err error) {
	var stmt *sqlite.Stmt
	if stmt, _, err = conn.PrepareTransient(query.QueryStr); err != nil {
		return nil, err
	}
	defer finalize(stmt, &err) // always finalize to prevent resource leaks

	if stmt.BindParamCount() > 0 {
		if err = query.Bind(stmt); err != nil { // bind all variables to the statement
			return nil, err
		}
	}

	var result, has = make([]*M, 0), false
	for has, err = stmt.Step(); has && err == nil; has, err = stmt.Step() {
		var m *M
		if m, err = query.Val(stmt); err != nil {
			return nil, err
		}
		result = append(result, m)
	}

	return result, err
}

// FetchOne runs the given query and returns either nil or a single instance of M
func FetchOne[M any](conn *sqlite.Conn, query Q[M]) (_ *M, err error) {
	var stmt *sqlite.Stmt
	if stmt, _, err = conn.PrepareTransient(query.QueryStr); err != nil {
		return nil, err
	}
	defer finalize(stmt, &err) // always finalize to prevent resource leaks

	if stmt.BindParamCount() > 0 {
		if err = query.Bind(stmt); err != nil { // bind all variables to the statement
			return nil, err
		}
	}

	var has = false
	if has, err = stmt.Step(); has && err == nil {
		return query.Val(stmt)
	}

	return nil, err
}

// I represents a sqlite write statement, ie. one of INSERT / UPDATE / DELETE.
type I[M, A any] struct {
	// QueryStr is the sql query used to create a prepared statement
	QueryStr string

	// ArgSet is a set of values that are inserted / updated / deleted using
	// a single prepared statement, i.e. the execution of the query is batched together.
	ArgSet []A

	// Bind is used to bind any variables to the given statement
	Bind func(stmt *sqlite.Stmt, args A) error

	// Val is used to extract values from the statement and create a new instance of M.
	// Val can be omitted if QueryStr does not return any rows (eg. INSERT without a RETURNING clause)
	Val func(stmt *sqlite.Stmt) (*M, error)
}

// Exec executes the given query and returns a slice of zero or more instances of M, if the query return any rows.
func Exec[M, A any](conn *sqlite.Conn, query I[M, A]) (_ []*M, err error) {
	var stmt *sqlite.Stmt
	if stmt, _, err = conn.PrepareTransient(query.QueryStr); err != nil {
		return nil, err
	}
	defer finalize(stmt, &err) // always finalize to prevent resource leaks

	var result, has = make([]*M, 0), false
	for _, arg := range query.ArgSet {
		if err = query.Bind(stmt, arg); err != nil { // bind all variables to the statement
			return nil, err
		}

		if has, err = stmt.Step(); has && err == nil {
			var m *M
			if m, err = query.Val(stmt); err != nil {
				return nil, err
			}
			result = append(result, m)
		} else if err != nil {
			return nil, err
		}
		_, _ = stmt.ClearBindings(), stmt.Reset()
	}

	return result, nil
}

// Tx starts a new transaction and executes the given fn, rolling back if fn returns an error or panics.
//
// This is a utility function for use when directly calling sqlitex.Save would be awkward. Use of this
// function should be an exception rather than a norm. Use sqlitex.Save directly when possible.
//
// See also: sqlitex.Save
func Tx(conn *sqlite.Conn, fn func(*sqlite.Conn) error) (err error) {
	defer sqlitex.Save(conn)(&err)
	return fn(conn)
}

func finalize(stmt *sqlite.Stmt, err *error) {
	if fe := stmt.Finalize(); fe != nil && *err == nil {
		*err = fe
	}
}
