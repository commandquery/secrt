--
-- Test the activation function. This is obviously a critical function in the server.
--
create or replace
    function secrt.activate_test()
      returns void language 'plpgsql' as $$
    declare
        _token bytea;
        _code integer;
        _alias text;
        _peer_id uuid;
        _peer secrt.peer;
        _public_key bytea = gen_random_bytes(32);
        _default_key bytea;
        _server uuid = gen_random_uuid();

    begin
        insert into secrt.server (server, secret_box_key, private_box_key, public_box_key, private_sign_key, public_sign_key)
            values (_server, gen_random_bytes(16), gen_random_bytes(16), gen_random_bytes(16), gen_random_bytes(16), gen_random_bytes(16));

        select * into _token, _code from secrt.enrol(_server, 'test@example.com', _public_key);

        select * into _peer_id, _alias from secrt.activate(_token, _code);

        perform _alias =? 'test@example.com';

        select * into _peer from secrt.peer where server=_server and alias=_alias;
        if not found then
            raise exception 'activated peer not found';
        end if;

        select public_key into _default_key from secrt.key where key=_peer.default_key;

        perform ??(_default_key = _public_key);
        perform ??(_peer.peer = _peer_id);
        perform ??(_peer.server = _server);

    end;
$$;