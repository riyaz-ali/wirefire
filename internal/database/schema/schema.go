// Package schema provides the sqlite schema migrations and utility functions to apply those.
package schema

import (
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"embed"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"sort"
)

//go:embed *.sql
var root embed.FS // embedded migration scripts

// Apply applies all the pending schema migrations to the primary database
// in the provided sqlite connection. It increments the user_version and set
// it to the latest value for the last migration that was executed.
func Apply(c *sqlite.Conn) (err error) {
	defer sqlitex.Save(c)(&err) // migrations are transactional!

	var getVersion = func() int {
		var v int
		_ = sqlitex.Exec(c, "PRAGMA user_version",
			func(stmt *sqlite.Stmt) error { v = int(stmt.GetInt64("user_version")); return nil })
		return v
	}

	var setVersion = func(v int64) error {
		return sqlitex.Exec(c, fmt.Sprintf("PRAGMA user_version = %d", v), nil)
	}

	var migrations = ReadMigrations(root)
	sort.Stable(migrations) // sort in ascending order of version number

	log.Info().Msgf("current migration version is v%d", getVersion())
	for _, mg := range migrations {
		if mg.Version() <= getVersion() {
			log.Debug().Str("file", mg.Name()).Msgf("skipping version v%d", mg.Version())
			continue // already applied. skip this migration
		}

		log.Info().Str("file", mg.Name()).Msgf("applying script version v%d", mg.Version())
		if err = mg.Apply(c); err != nil {
			return errors.Wrapf(err, "failed to apply migration: name=%s\tversion=%d", mg.Name(), mg.Version())
		}

		if err = setVersion(int64(mg.Version())); err != nil {
			return errors.Wrapf(err, "failed to update version to v%d", mg.Version())
		}
	}

	return nil
}
