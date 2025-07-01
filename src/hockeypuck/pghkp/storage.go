/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pghkp

import (
	"database/sql"
	"strings"
	"sync"

	"gopkg.in/tomb.v2"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
)

const (
	maxInsertErrors = 100
)

type storage struct {
	*sql.DB
	dbName  string // TODO: remove this field, it is not used in the codebase
	options []openpgp.KeyReaderOption

	mu        sync.Mutex
	listeners []func(hkpstorage.KeyChange) error

	t tomb.Tomb
}

var _ hkpstorage.Storage = (*storage)(nil)

// These are necessary for array unrolling in the bulk update routines below.
// They MUST match the table definitions here.
const keysNumColumns = 7
const subkeysNumColumns = 2

var crTablesSQL = []string{
	// keys is always created with its initial six columns.
	// Additional columns should be defined using ALTER TABLE to enable seamless migration.
	`CREATE TABLE IF NOT EXISTS keys
(
rfingerprint TEXT NOT NULL PRIMARY KEY,
doc jsonb NOT NULL,
ctime TIMESTAMPTZ NOT NULL,
mtime TIMESTAMPTZ NOT NULL,
md5 TEXT NOT NULL UNIQUE,
keywords tsvector
)`,
	// For seamless migration, we use NOT NULL DEFAULT so that existing records get populated.
	// Then we immediately DROP DEFAULT to force future records to be set explicitly.
	`ALTER TABLE keys ADD IF NOT EXISTS idxtime
TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'`,
	`ALTER TABLE keys ALTER idxtime
DROP DEFAULT`,
	// subkeys is always created with its initial two columns.
	// Additional columns should be defined using ALTER TABLE to enable seamless migration.
	`CREATE TABLE IF NOT EXISTS subkeys
(
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL PRIMARY KEY,
FOREIGN KEY (rfingerprint) REFERENCES keys(rfingerprint)
)
`,
	`CREATE TABLE IF NOT EXISTS pks_status (
	addr TEXT NOT NULL PRIMARY KEY,
	last_sync TIMESTAMP WITH TIME ZONE,
	last_error TEXT
	)
`,
}

var crIndexesSQL = []string{
	`CREATE INDEX IF NOT EXISTS keys_rfp
ON keys(rfingerprint text_pattern_ops);`,
	`CREATE INDEX IF NOT EXISTS keys_ctime
ON keys(ctime);`,
	`CREATE INDEX IF NOT EXISTS keys_mtime
ON keys(mtime);`,
	`CREATE INDEX IF NOT EXISTS keys_idxtime
ON keys(idxtime);`,
	`CREATE INDEX IF NOT EXISTS keys_keywords
ON keys USING gin(keywords);`,
	`CREATE INDEX IF NOT EXISTS subkeys_rfp
ON subkeys(rsubfp text_pattern_ops);`,
}

// drConstraintsSQL is a list of SQL statements to drop constraints and indexes
// TODO: Remove if not needed
var drConstraintsSQL = []string{
	`ALTER TABLE keys DROP CONSTRAINT keys_pk;`,
	`ALTER TABLE keys DROP CONSTRAINT keys_md5;`,
	`DROP INDEX keys_rfp;`,
	`DROP INDEX keys_ctime;`,
	`DROP INDEX keys_mtime;`,
	`DROP INDEX keys_idxtime;`,
	`DROP INDEX keys_keywords;`,

	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_pk;`,
	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_fk;`,
	`DROP INDEX subkeys_rfp;`,
}

// Dial returns PostgreSQL storage connected to the given database URL.
func Dial(url string, options []openpgp.KeyReaderOption) (hkpstorage.Storage, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return New(db, options)
}

// New returns a PostgreSQL storage implementation for an HKP service.
func New(db *sql.DB, options []openpgp.KeyReaderOption) (hkpstorage.Storage, error) {
	st := &storage{
		DB:      db,
		options: options,
	}
	err := st.createTables()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create tables")
	}
	err = st.createIndexes()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create indexes")
	}
	return st, nil
}

// Convert up to the first newline of the input string to a space-free identifier.
// Useful when we haven't created a statement array programmatically but still want pretty logs.
func sqlDesc(in []string) (out []string) {
	out = make([]string, 0, len(in))
	for _, val := range in {
		init, _, _ := strings.Cut(val, "\n")
		out = append(out, strings.Replace(init, " ", "_", -1))
	}
	return
}

func (st *storage) createTables() error {
	err := st.bulkExecSingleTx(crTablesSQL, sqlDesc(crTablesSQL))
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (st *storage) createIndexes() error {
	err := st.bulkExecSingleTx(crIndexesSQL, sqlDesc(crIndexesSQL))
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
