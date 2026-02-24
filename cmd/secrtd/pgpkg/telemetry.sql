create or replace
    function secrt.post_telemetry(_ip text, t jsonb)
      returns void language 'plpgsql' as $$
    declare
    begin
        insert into secrt.telemetry (ip, build_id, goos, goarch, command, elapsed_ms, utime_ms, stime_ms, exit_code)
            values (
                    _ip,
                    t ->> 'buildId',
                    t ->> 'goos',
                    t ->> 'goarch',
                    t ->> 'command',
                    (t ->> 'elapsedMs')::integer,
                    (t ->> 'utimeMs')::integer,
                    (t ->> 'stimeMs')::integer,
                    (t ->> 'exitCode')::integer
                        );
    end;
$$;