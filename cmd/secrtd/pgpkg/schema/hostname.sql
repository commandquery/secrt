create table secrt.hostname (
    hostname text not null primary key,
    server uuid not null references secrt.server (server)
)