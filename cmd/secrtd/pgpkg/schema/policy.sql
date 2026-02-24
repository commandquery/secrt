--
-- a policy specifies the limits or rules that apply to
-- a particular user or group of users.
--

create table secrt.policy
(
    policy                   uuid    not null primary key default pg_catalog.gen_random_uuid(),
    counter_interval_seconds integer not null, -- how long we collect counters

    message_count_limit      integer not null, -- how many messages we can send in the interval
    message_byte_limit       integer not null, -- max size of a single message
    message_bandwidth_limit  integer not null, -- how many bytes we can send per counter
    invite_count_limit       integer not null, -- how many invites we can send
    message_expiry_seconds   integer           -- max time we will store messages, null means no limit
);

insert into secrt.policy (policy, counter_interval_seconds, message_byte_limit, message_count_limit, message_bandwidth_limit, invite_count_limit, message_expiry_seconds)
    values ('A26FCB5C-E28A-4D7B-99AC-6D3468E7CF31', 604800, 5*1024, 25, 25*5*1024*7, 50, 14400);
