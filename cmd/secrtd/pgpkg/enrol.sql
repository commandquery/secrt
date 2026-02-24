--
-- Generate an enrolment token with a random key.
--

create or replace
    function secrt.enrol(_server uuid, _alias text, _public_key bytea, out _token bytea, out _code integer)
      returns record language 'plpgsql' as $$
    declare
    begin
        _token = gen_random_bytes(16);
        _code = floor(random() * 999999 + 1)::integer;

        -- cancel any previous enrolment requests
        delete from secrt.activation where server=_server and alias=_alias;

        insert into secrt.activation (token, code, server, alias, public_box_key)
            values (_token, _code, _server, _alias, _public_key);

        return;
    end;
$$;