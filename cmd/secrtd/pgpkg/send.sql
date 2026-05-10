--
-- Send a message after updating the policies.
--

create or replace
    function secrt.send(_message_k uuid, _sender uuid, _recipient uuid, _server uuid, _metadata bytea, _payload bytea, _claims bytea)
      returns uuid language 'plpgsql' as $$
    declare
        _delta secrt.counter;
        _policies uuid[];
        _expires timestamptz;
        _max_expiry_seconds integer;
        _seq integer = 0;
    begin
        _delta = secrt.delta(
            message_count => 1,
            byte_count => octet_length(_payload) + octet_length(_metadata)
        );

        _policies = secrt.update_pools(_sender, _delta);

        _max_expiry_seconds = min(message_expiry_seconds)
            from secrt.policy where policy = any(_policies) and message_expiry_seconds is not null;
        _expires = current_timestamp + (_max_expiry_seconds * '1 second'::interval);

        insert into secrt.seq (peer, next) values (_recipient, 1)
            on conflict (peer) do update set next=secrt.seq.next+1 returning next into _seq;

        insert into secrt.message (message, peer, seq, server, received, expires, metadata, payload, claims)
            values (_message_k, _recipient, _seq, _server, current_timestamp, _expires, _metadata, _payload, _claims);

        return _message_k;
    end;
$$;