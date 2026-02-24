create table secrt.message (
    primary key (peer, message),

    peer uuid not null,
    message uuid not null,
    server uuid not null references secrt.server,
	received timestamptz not null,
    expires timestamptz,
	claims bytea not null,     -- contains the sending peer alias, server-sealed
    metadata bytea,
	payload bytea not null
);

create index message_expiry_idx on secrt.message (expires);