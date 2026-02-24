--
-- returns the current counter for the given pool.
-- If the counter doesn't exist, it gets created.
-- This is trickier than it looks because the counter
-- timestamp needs to be some multiple of policy intervals,
-- and it might not currently exist.
--
create or replace
    function secrt.counter(_pool secrt.pool, _policy secrt.policy)
        returns secrt.counter language 'plpgsql' as $$
    declare
        _counter secrt.counter;
        _start_seconds integer;
        _counter_start timestamptz;
    begin
        _start_seconds = floor(extract(epoch from current_timestamp - _pool.start) / _policy.counter_interval_seconds) * _policy.counter_interval_seconds;
        _counter_start = _pool.start + (_start_seconds * '1 second'::interval);

        select * into _counter from secrt.counter where start=_counter_start and pool=_pool.pool;
        if not found then
            insert into secrt.counter (pool, start) values (_pool.pool, _counter_start) returning * into _counter;
        end if;

        return _counter;
    end;
$$;

--
-- Check the policy against the delta. If the delta would violate the policy, throws an exception.
--
create or replace
    function secrt.update_pool(_pool secrt.pool, _policy secrt.policy, _delta secrt.counter)
      returns void language 'plpgsql' as $$
    declare
        _old secrt.counter;
        _new secrt.counter;
    begin
        if _delta.byte_count > _policy.message_byte_limit then
            raise exception 'message size limit exceeded';
        end if;

        _old = secrt.counter(_pool, _policy);

        _new.message_count = _old.message_count + _delta.message_count;
        _new.byte_count = _old.byte_count + _delta.byte_count;
        _new.invite_count = _old.invite_count + _delta.invite_count;

        if _new.message_count > _policy.message_count_limit then
            raise exception 'message count quota exceeded';
        end if;

        if _new.byte_count > _policy.message_bandwidth_limit then
            raise exception 'message bandwidth quota exceeded';
        end if;

        if _new.invite_count > _policy.invite_count_limit then
            raise exception 'invite quota exceeded';
        end if;

        update secrt.counter set (message_count, byte_count, invite_count) =
            (_new.message_count, _new.byte_count, _new.invite_count)
                where pool=_old.pool and start=_old.start returning * into _new;

    end;
$$;

--
-- Iterate through all the pools and policies associated with the sender,
-- checking the policies and updating the pools as we go.
--
-- Different policies will have different sampling (pools) which means that
-- we have to treat them all
--
-- Returns the list of policy IDs associated with the peer's pools.
--
create or replace
    function secrt.update_pools(_sender uuid, _delta secrt.counter)
      returns uuid[] language 'plpgsql' as $$
    declare
        _pools uuid[];
        _pool_k uuid;
        _pool secrt.pool;
        _policy secrt.policy;
        _policies uuid[];
    begin
        select pools into _pools from secrt.peer where peer=_sender;
        foreach _pool_k in array _pools loop
            select * into strict _pool from secrt.pool where pool=_pool_k;
            select * into strict _policy from secrt.policy where policy=_pool.policy;
            _policies = _policies || _pool.policy;
            perform secrt.update_pool(_pool, _policy, _delta);
        end loop;

        return _policies;
    end;
$$;