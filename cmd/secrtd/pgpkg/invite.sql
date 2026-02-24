--
-- This is just a policy check for invites and does not actually store anything.
-- If the policy will be violated, raises an exception.
-- Returns true if the peer already exists.
--
create or replace
    function secrt.invite(_server uuid, _sender uuid, _alias text)
    returns boolean language 'plpgsql' as $$
declare
    _delta secrt.counter;
begin
    perform 1 from secrt.peer where server=_server and alias=_alias;
    if found then
        return true;
    end if;

    _delta = secrt.delta(invite_count => 1);
    perform secrt.update_pools(_sender, _delta);
    return false;
end;
$$;