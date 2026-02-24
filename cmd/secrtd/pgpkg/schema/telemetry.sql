--
-- Log stats about the performance of the application.
--
create table secrt.telemetry (
    ip text not null,
    timestamp timestamptz not null default current_timestamp,
    build_id text not null,
    goos text,
    goarch text,
    command text,
    elapsed_ms integer,
    utime_ms integer,
    stime_ms integer,
    exit_code integer
);