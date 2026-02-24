--
-- the activate function finds the given activation key and deletes it.
-- it also deletes any expired keys. It then creates a new peer for the given
-- alias. Returns the peer ID and associated alias.
--
create or replace
    function secrt.activate(_token bytea, _code int, out _peer uuid, out _alias text, out _public_key bytea)
       language 'plpgsql' as $$
    declare
        _activation secrt.activation;
        _server secrt.server;
        _policy uuid;
        _pool uuid;
        _pools uuid[];
    begin
        -- quick purge of old activation tokens
        delete from secrt.activation where expiry <= current_timestamp;
        delete from secrt.activation where token=_token and code=_code returning * into _activation;
        if not found then
            raise exception 'activation token not found';
        end if;

        perform 1 from secrt.peer where server=_activation.server and peer.alias=_activation.alias;
        if found then
            raise exception 'peer is already activated';
        end if;


        --
        -- Assign and/or create pools based on the server configuration.
        --
        select * into strict _server from secrt.server where server=_activation.server;
        _pools = _pools || _server.pools;

        if _server.peer_policies is not null then
            foreach _policy in array _server.peer_policies loop
                insert into secrt.pool (pool, policy) values (default, _policy) returning pool into _pool;
                _pools = _pools || _pool;
            end loop;
        end if;

        insert into secrt.peer (server, peer, alias, pools, public_box_key)
            values (_activation.server, DEFAULT, _activation.alias, array[_pool], _activation.public_box_key)
            returning peer into _peer;

        _alias = _activation.alias;
        _public_key = _activation.public_box_key;

        raise notice 'successfully activated alias %', _activation.alias;
    end;
$$;

