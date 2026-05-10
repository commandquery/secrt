--
-- The sequence table simply maintains a list of message sequence numbers
-- on a per-peer basis so that messages can be efficiently retrieved based
-- on the sequence number. We maintain sequence numbers on a per-peer basis
-- so we don't expose information about the server. We store it in a separate
-- table so we can optomise it, or move it to more efficient storage, as needed.
--
create table secrt.seq (
    peer uuid not null primary key,
    next integer not null default 0
);