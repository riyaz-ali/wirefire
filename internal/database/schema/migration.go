package schema

import (
	"bytes"
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"embed"
	"fmt"
	"io/fs"
	"path"
)

// Migration represents a single sql migration, that can apply any combination of DDL + DML to alter the database.
type Migration interface {

	// Name returns the user-friendly name of the migration.
	Name() string

	// Version returns an incremental version number for this migration
	Version() int

	// Apply applies the given migration to the provided connection
	Apply(*sqlite.Conn) error
}

type EmbeddedMigration struct {
	name string
	buf  bytes.Buffer
}

func (e *EmbeddedMigration) Name() string               { return e.name }
func (e *EmbeddedMigration) Version() (v int)           { _, _ = fmt.Sscanf(e.Name(), "v%d.sql", &v); return v }
func (e *EmbeddedMigration) Apply(c *sqlite.Conn) error { return sqlitex.ExecScript(c, e.buf.String()) }

type EmbeddedMigrations []*EmbeddedMigration

func (e EmbeddedMigrations) Len() int           { return len(e) }
func (e EmbeddedMigrations) Less(i, j int) bool { return e[i].Version() < e[j].Version() }
func (e EmbeddedMigrations) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }

func ReadMigrations(root embed.FS) EmbeddedMigrations {
	var all EmbeddedMigrations
	_ = fs.WalkDir(root, ".", func(name string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}

		var file, _ = root.Open(name) // no need to close on embedded file
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(file)

		all = append(all, &EmbeddedMigration{name: path.Base(name), buf: buf})

		return nil
	})
	return all
}
