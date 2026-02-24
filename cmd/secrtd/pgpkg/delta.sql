create or replace
    function secrt.delta(
        message_count integer default 0,
        byte_count integer default 0,
        invite_count integer default 0
    ) returns secrt.counter language 'plpgsql' as $$
    declare
        _delta secrt.counter;
    begin
        _delta.message_count = message_count;
        _delta.byte_count = byte_count;
        _delta.invite_count = invite_count;
        return _delta;
    end;
$$;