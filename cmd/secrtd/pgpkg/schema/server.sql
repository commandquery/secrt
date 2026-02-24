create table secrt.server (
    server uuid not null primary key default gen_random_uuid(),

    -- The signing and encryption keys for talking to server itself.
    secret_box_key bytea not null,  -- symmetric key, used for sending invites
    private_box_key bytea not null, -- asymmetric private key
    public_box_key bytea not null,
    private_sign_key bytea not null,
    public_sign_key bytea not null,

    -- per-peer policy pools, e.g. for AUP.
    peer_policies uuid[] not null default array['A26FCB5C-E28A-4D7B-99AC-6D3468E7CF31']::uuid[],

    -- all peers for this service are added to this pool.
    pools uuid[]
);