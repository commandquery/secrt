create table secrt.peer (
    primary key (peer),
    unique (server, alias),

    peer uuid not null default gen_random_uuid(),
    server uuid not null references secrt.server,
    alias text not null,

    pools uuid[] not null,
    public_box_key bytea not null
);