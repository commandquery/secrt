# not-so-secret TODO

- [ ] how to deal with public key changes?
  - [X] make it possible for a peer to have multiple public keys
  - [X] error out if public key for a peer on a message doesn't match the cached one.
  - [ ] test: re-enrol and existing peer, send a message and receive it
    - [ ] this will need some mechanism to trust new peer keys - could be as simple as "secrt peer trust user@domain"
  - [ ] need config migration tests

## Secret Sync

- the idea is that each enrolled instance of secrt has both a "group" and an "instance" private key
- the "instance" private key is unique to each instance, while the "group" key is shared among them.
- we use the instance private key to share the group key.
- senders use the group key to send messages to a peer
- there can actually be any number of groups, but one of them is a "my devices" group
- syncing is enabled by storing messages on the server for a long time. that's it!
- how to migrate??

## Soft Launch Blockers / bugs
- [ ] ability to pin/save secrets, esp. for use with `secrt run`
  - can't use metadata or claims, they are signed by the sender/server
  - save names locally
- [ ] let the config be exported/imported with a random, separate passphrase / ssh integration??
- [ ] search for secrets by pinned name / tag
- [ ] Support for a "upgrade required" status on all API responses - http 426
- [ ] support for "please upgrade" (or something) header - for soft upgrade 
- [ ] user docs
- [ ] "* If you didn't expect a message from mark.lillywhite@emersion.com, don't trust it." -- when SENDING!
- [ ] bring back short message listings
- [ ] activation command doesn't send a token nor a challenge
- [ ] how does activation token work, can we send a token in enrolment to allow web activation?

## Client

- [ ] `secrt purge` - remove expired secrets from cache
- [ ] `secrt keep` - flag cached secrets so they aren't purged 
- [ ] add test to ensure telemetry disabling works (check database size)
- [ ] add test to ensure that disabling the cache disables it
  - disabling the cache should remove any cached messages (or tell user to use `secrt purge`)
- [ ] need to print a message on enrolment explaining how to disable telemetry and stop accepting peers
- [ ] display expiry time in secrets
- [ ] endpoints might have multiple primary keys (senders) but shouldn't they share the peers list?
- [ ] how to prevent unwanted messages / spam? block user until authorised? block/report address?
  - [ ] require invite from one side?
  - [ ] block lists?

## Server Features

- [ ] peers belong to zero or more servers, any number of servers
- [ ] server features kick in when two peers are on the same server
- [ ] that's possibly all we need
- [ ] restricted by email patterns and/or by invite
- [ ] secret groups - see GROUPS.md

## Code Release

- [ ] reset the git history - start with latest version only

## Website

- [X] Privacy carve-out for anonymous telemetry
- [ ] fix console warning about tailwind css; the css is probably massive
- [ ] make sure website degrades gracefully without javascript

## Server Console / Vibe Coding

> NOTES:
> * Start testing with friends and family before starting work on the server console
> * this is a totally separate project, not part of the open source tools

- [ ] list peers
- [ ] delete peer
- [ ] invite peer (peers still need to generate their own keys)
- [ ] change invoice details
- [ ] cancel subscription
- [ ] dns instructions and checks

## Server

- [ ] upon activation, server should send a secret welcome message to the client.
    - [ ] this means the server needs to be a peer!
    - [X] client should print activation welcome message (already sent by server)
- [ ] policy tests: single policies, AUP (private server) policies
- [ ] need maximum message size limits in dispatchJS (http.MaxBytesReader) and configurable (lower) limits in handlePostMessage 
- [ ] deploy as an actual service (kill the version running at emersion)
- [ ] make available in homebrew
- [ ] review all the code analysis warnings
- [ ] get claude to check the code
- [ ] share with mark.dorset@, richard@, noel@, stephan@ ... what about the pgpkg guy? Felix

## Notes for code review and LLM review

- run `go vet` and maybe `go fix`
- look for consistent use of "alias" and not "user" or "email" or "peerID" or otherwise
- in the client, make sure we use request context and not context.Background(). DO NOT use request context in the server.

## Future

- [ ] CLI option to set expiry time in secrets (including none)
- [ ] cache retreived secrets (should then be visible in 'secrt ls')
- [ ] user-friendly support for multiple servers (eg, list endpoints and select one)
- [ ] "machine" support - store .env or other config in a secret.
  - secrt enrol-machine xyz -> prints the private key on the command line
    - generates a private config json for the machine
    - json contains the private key and a list of accepted peers
    - machine policy should not allow sending messages
  - how can ops@example.com see what the secret values were (hint: encrypt for both the machine and self)
  - how can the host reliably get the latest version of the secret (use filenames/metadata and retrieve latest?)
  - how do we configure the host in the first place? what about kubernetes?
  - how to set the environment in the first place? `secrt exec mysecret.env -- ...`?

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
- [X] private key is a structure containing key type
- [X] use platform keystore to store passwords by default
- [X] platform "User" field needs to include the peerId as well as the server ID (since we can have different configs in -f)
- [X] in "secrt send", the filename should come *before* the peer address - so we can send to multiple peers
- [X] send secrets to multiple people
- [X] "secrt invite user@domain" - sends an email with download instructions
- [X] saving client config should be atomic / write to a temp file then move it.
- [X] enrolment for same peer ID and same server should require --force
- [X] enrolment should use hashcash to limit mass enrolment
- [X] verify the nonce headers on the server size
- [X] spend more time ensuring that hashcash is really working properly
- [X] postgres backend
- [X] test that sending to an unknown peer doesn't crash the server (!)
- [X] some nice JSON wrappers for sending and receiving JSON - readJSON and writeJSON generics?
- [X] replace http.ServeFunc with ?? ServeAPI[T] ?
- [X] finish converting handlers to use dispatchJS
- [X] some nice JSON wrappers for sending and receiving JSON
- [X] client should use a http.Client (not http.DefaultClient) that has reasonable timeouts
- [X] client should always print the full UUID. you can optionally just use the prefix.
- [X] finish account activation -> actual enrolment via email - REVIEW
- [X] enrolment workflow - REVIEW
    - [X] enrolment messages (to the CLI) should come from the server!
    - [X] send email during enrolment.
    - [X] client should JSON to server with public key instead of binary (allows extension later)
    - [X] handleEnrol should return server public key as JSON instead of binary (allows extension later)
- [X] reduce the activation token size
    - [X] store activation codes on the server
    - [X] reduces token size and lets us rate limit too
- [X] need to use LogError instead of WriteStatus in http handlers (instead of _ = WriteStatus(...))
- [X] email enrolment verification (if required and available with server config)
- [X] activation URL (ie, target for activation link)
- [X] defer "adding new peer" messages ("warning: added new peer") until client exits
- [X] public key lookup changes:
    - [X] sender's public key is now in the message claims
    - [X] client needs to compare with existing key, add it if not found and auto-enabled
- [X] BUG: secret ls can't get peers because it expects a sender. add peer from claims instead
    - [X] enrolment handshake needs to return server's public box key
- [X] need to validate that the claim metadata and payload hashes match the actual payload and metadata
- [X] add server-sealed claims to messages
- [X] use claim data in ls and get
- [X] remove sender from message table
- [X] strengthen GetSignature() / authentication:
    - [X] enrolment/auth should respond with a server-secret token containing the peer details, + public key
    - [X] save the token using the same mechanism as password (eg, platform)
    - [X] send the token in all calls
    - [X] decrypt the token on the server side, replace signature with token
    - [X] remove old signature code/headers from the client side
- [X] remove google fonts and tailwind cdn / privacy
- [X] auth token needs an issue time rather than a token ID, to enable revocation / forced logout
- [X] auth key needs to contain the public key to ensure it's not been copied
- [X] check public key in auth key matches peer's actual public key
- [X] use hashes instead of aliases. NO - if you want that level of privacy, run your own server. otherwise i can't talk to customers.
- [X] enrol endpoint doesn't need alias in url, send it as the request
- [X] FIX: peers and messages should NOT include server in the primary key - server is not a tenant ID!
    - [X] remove server from peer key
    - [X] check lookups and indexes
- [X] set expiry time on messages
- [X] purge messages periodically
- [X] invitations
    - [X] just allow people to invite other people from the command line, no tracking
    - [X] log invite date/time/sender but not recipient
    - [X] limits are policy based, paid servers are domain-restricted
- [X] GetPeer should not send the alias in the URL
- [X] PostMessage should not send the recipient in the URL
- [X] need server-side message size limit enforcement
- [X] need to automatically purge old messages from SQL
- [X] policy support
    - [X] explicit pool membership, membership of multiple pools
    - [X] enforcement mechanism - create a proposed delta within the transaction and test it against each policy.
    - [X] daily limits, message size limits, timezone, secret expiry, invites, device count
    - [X] invite limits
- [X] some kind of usage limits / AUP / rate limiting - a byte limit would satisfy my problem with nasty material
- [X] add a mode to dump the JSON in http calls
- [X] enable invitations
- [X] send performance data - consider app-version GOOS GOARCH num-cpus command exit-code cpu-time-ms elapsed-time-ms max-rss-kb total-alloc-kb peak-goroutines go-version
- [X] store the telemetry in the database
- [X] rename "publicBoxKey" (etc) to BoxPublicKey, etc
    - [X] PublicBoxKey
    - [X] PrivateBoxKey
- [X] make sure the client config field names match the server-side names
    - eg server.publicKey should probably be publicBoxKey? publicSignKey?
- [X] message ID and timestamp should be in the claims
- [X] secrt.Inbox just contains all messages, better to just send message IDs
    - [X] Inbox only returns message IDs
    - [X] client calls GetMessage on each ID
    - [X] -c needs to specify a directory
    - [X] need to be able to disable message caching (env or setting)
    - [X] messages are cached, GetMessage returns cached messages if avail.
- [X] `secrt ls` should list all messages in cache as well as any new messages
- [X] short message IDs can be used to find cached messages
- [X] where does the client get the server signing key for claims? or are they encrypted
- [X] secrt rm should accept short ids
- [X] carefully review the API, it will be a pain to change later.
- [X] secrt ls doesn't display the cache entry in my own cache!
- [X] implement a cache as the top-level primitive in the server
- [X] implement cache.pull() on client and server
