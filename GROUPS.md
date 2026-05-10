# Secret Groups

Do we even want groups? I'm not actually sure ... what I think I want is machine accounts


Groups are a simple configuration stored on the server as a message.

Group messages are encrypted using a DEK, the DEK is shared with members using a group message, the same
message is sent to all recipients simultaneously (ie, a message can have many recipients - this requires a
schema change)

you need a server subscription to create a group because groups require pinned messages.

groups maintain privacy, group configuration is protected by the DEK.

* messages are immutable, but we need a way to publish new group configurations
* sometimes we also want to be able to modify a message previously sent
* to this end:
  * create a general mechanism for updating an existing message (ie, an "updates" ID?)
  * update message must have same expiry as original message
  * need a message-type field (plain message, group message, group config, update)
  * make message recipients an array / gin index

problem:
- we don't want to see who belongs to which group
- so we need some concept of a group ID that recipients can poll
- this would be an index of uuids for all messages in the group




- groups are a set of public keys - admins, senders and receivers
- clients download the group config
- group config must be signed by one of the group admins
- pinned secrets - no expiry time - everyone in the group gets the latest secret
- enrol a machine in a group, keep the private key on the machine, don't need to copy it
- re-enrol a machine by generating a new key - web UI or CLI to add it
- sharing a secret with a group will share it with all machines in that group
- re-enroling happens automagically
