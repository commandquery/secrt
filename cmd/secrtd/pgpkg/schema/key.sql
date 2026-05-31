--
-- List of public keys for a peer.
--
-- Multiple devices can be enrolled with a single peer ID, and the way this works
-- is that each device has its own private key, and there is a group key which is
-- shared between devices.
--
-- Note also that a key can be replaced, but we still need a record of past keys
-- in order to be able to authenticate old messages.
--

create type secrt.key_type_e as enum ('box');

create table secrt.key (
    primary key (peer, key),

    key uuid not null default gen_random_uuid(),
    public_key bytea not null,
    type secrt.key_type_e not null,
    peer uuid not null references secrt.peer (peer)
);

insert into secrt.key (public_key, type, peer) select public_box_key, 'box', peer from secrt.peer;