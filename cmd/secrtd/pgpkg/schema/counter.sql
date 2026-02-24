--
-- Counters collect statistics about message usage, and are used to make
-- policy decisions.
--
-- Look up counters by computing the start time of the current period.
--
create table secrt.counter (
    primary key (pool, start),

    pool uuid not null references secrt.pool,
    start timestamptz not null,

    message_count integer not null default 0,
    byte_count integer not null default 0,
    invite_count integer not null default 0
);