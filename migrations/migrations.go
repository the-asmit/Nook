// Package migrations embeds Nook's goose SQL migrations so every
// nook-server binary carries exactly the schema version it was built for.
//
// Create new files with `make migrate-new name=<description>`; never edit a
// migration that has been committed, add a new one instead.
package migrations

import "embed"

// FS contains the migration files, named NNNNN_description.sql.
//
//go:embed *.sql
var FS embed.FS
