module github.com/commandquery/secrt

go 1.24.0

toolchain go1.24.2

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.8.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/pgpkg/pgpkg v0.0.0-00010101000000-000000000000
	github.com/wneessen/go-mail v0.7.2
	github.com/zalando/go-keyring v0.2.6
	golang.org/x/crypto v0.45.0
	golang.org/x/term v0.37.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lib/pq v1.10.7 // indirect
	github.com/pganalyze/pg_query_go/v6 v6.1.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/wasilibs/go-pgquery v0.0.0-20250409022910-10ac41983c07 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/pgpkg/pgpkg => ../pgpkg
