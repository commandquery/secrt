# not-so-secret TODO

- [ ] send secrets to multiple people
- [ ] deploy as an actual service (kill the version running at emersion)
- [ ] protect the private key on the client (eg with a passphrase)
- [ ] support for multiple servers (eg, -s server)
- [ ] server-side struct mutations aren't generally protected by a mutex.
- [ ] saving client or server config should be atomic
  - [ ] write to a temp file then move it.

## Commercial & Public Stuff

- [ ] postgres backend
- [ ] invite mechanism. - invite specific users, invite an entire domain
- [ ] email invite verification
- [ ] some kind of usage limits / AUP / rate limiting - a byte limit would satisfy my problem with nasty material
- [ ] make available in homebrew
- [ ] web site
- [ ] share with mark.dorset@... (SECRET_AUTO_ENROL="invite"), richard@, noel@, ... what about the pgpkg guy?

## Done

- [X] allow the token for "secret add" to be a parameter rather than stdin
- [X] signature verification - can't sign messages using encryption key:
    - [X] add server public key to config
    - [X] encrypt a message for the server
    - [X] Signature: mark.lillywhite@emersion.com:xxxxxx
    - [X] "xxxx" is just the current timestamp, as a string
    - [X] encrypted for the server's public key, only the server can decrypt it
- [X] getPeer should download the peer key from the server if we don't have it.
    - [X] validate signature when getting public key for a peer (currently failing)
- [X] rename "UserID" to "PeerID"
- [X] need to be able to deploy with a static config for now (secret.emersion.com)
    - [X] add SECRET_AUTO_ENROL=approve option
    - [X] when set, this should log the peerID and key to the logs so I can add it manually
- [X] static config file
    - [X] configure in deployment descriptor
    - [X] SECRET_CONFIG=/path/to/config
    - [X] make it write-protected (if it isn't)
- [X] rename "secret send" to "secret share".
- [X] split client and server into their own packages, only put main.go in cmd/secret
    - [X] rename User to server.Peer
    - [X] move the README to top-level so we can print it in the usage text too
    - [X] refactoring needed in secret.go (eg, Client struct is the config, secret.go is actually about config)
    - [X] client.go should probably be endpoint.go?
- [X] print the sent message ID to the sender so they can help the receiver
- [X] `secrt set [property]=[value]` and especially `secrt set metadata=none`
- [X] `secrt set server=https://...` set default server
- [X] `secrt set acceptNewPeers=false` stop adding peers automatically
- [X] "-f conf" should point directly to a file, not a dir. (alice.secrt, bob.secrt)
- [X] I think a missing peer on the server causes a null pointer panic
- [X] rename "secret" to "secrt"
- [X] when a file is sent, also send a filename and size
    - [X] encrypt metadata, but store it separately.
    - [X] send encrypted metadata in "secrt ls"
    - [X] optionally send a description/subject
    - [X] "secrt ls -l" should show long uuid
    - [X] create a "ls" test with acceptNewPeers=false
- [X] client-side soft limit to size of payload and metadata in envelope
- [X] server-side hard limit to size of payload and metadata in envelope
- [X] `secrt rm` to remove a secret
- [X] `secrt get -o filename` to specify where to save a file
- [X] `secrt peer ls` list peers
- [X] `secrt peer rm user@example` remove peer
- [X] `secrt peer add user@example` explicitly add a peer
- [X] GET /peer/{peer} should return JSON rather than just the public key (eg, screen name)
