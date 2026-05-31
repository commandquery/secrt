--
-- A peer can have many different keys registered to it (eg, for many
-- different devices); the default key is key that we want senders to use to
-- send messages. This would generally be the *group* key for a peer, but
-- the group mechanism specifics aren't yet worked out as I write this.
--
alter table secrt.peer add column default_key uuid,
    add foreign key (peer, default_key) references secrt.key (peer, key) deferrable initially deferred;

update secrt.peer set default_key=key.key
    from secrt.key where key.peer = peer.peer;

alter table secrt.peer alter column default_key set not null,
    drop column public_box_key;