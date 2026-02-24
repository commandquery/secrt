package main

import (
	"embed"

	"github.com/pgpkg/pgpkg"
)

//go:embed pgpkg
var pgpkgSchema embed.FS

func mustInitPgpkg() {
	if err := pgpkg.ParseArgs("pgpkg"); err != nil {
		pgpkg.Exit(err)
	}

	project := pgpkg.NewProject()
	if _, err := project.AddEmbeddedFS(pgpkgSchema, "pgpkg"); err != nil {
		pgpkg.Exit(err)
	}

	// Migrate the database to the current version.
	if err := project.Migrate(Config.DatabaseDSN); err != nil {
		pgpkg.Exit(err)
	}
}
