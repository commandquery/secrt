--
-- this table contains the activation keys issued to potential peers.
-- activation codes last for 24 hours and can only be used once before they are deleted.
--
create table secrt.activation (
    primary key (token, code),

    token bytea not null,
    code integer not null,
    server uuid not null references secrt.server (server),
    alias text not null,
    public_box_key bytea not null,
    expiry timestamptz not null default current_timestamp + '24 hours'::interval
);

-- make it easy to delete old activations. a problem I'd like to have at this time!
create index activation_expiry_idx on secrt.activation (expiry);

-- make it easy to cancel existing activations, performed during enrolment.
create index activation_peer_ids on secrt.activation (server, alias);