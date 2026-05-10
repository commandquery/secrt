--
-- Add sequence numbers to messages to enable quick retrieval of new messages
-- using the new `pull` command.
--
create sequence secrt.migrate_sequence;
alter table secrt.message add column seq integer;
update secrt.message set seq=nextval('secrt.migrate_sequence');
alter table secrt.message alter column seq set not null;
alter table secrt.message add unique (peer, seq);
drop sequence secrt.migrate_sequence;