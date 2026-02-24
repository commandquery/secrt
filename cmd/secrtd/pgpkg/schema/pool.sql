--
-- A pool is a collection of peers that share a policy and a set of usage counters.
-- That is, every peer belongs to exactly one pool; a single pool may have multiple peers;
-- each pool collects counters and applies a usage policy.
--

create table secrt.pool (
    pool uuid not null primary key default pg_catalog.gen_random_uuid(),
    policy uuid not null references secrt.policy,
    start timestamptz not null default current_timestamp
);