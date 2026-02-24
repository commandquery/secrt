Secret: Securely exchange secrets with your peers.

Secret is a simple CLI command for exchanging sensitive data with your peers using
end-to-end encryption. Encrypted messages are stored temporarily on a server until
the peer picks them up.

All messages are encrypted with your private key. The server can never read your messages.

General usage:

    secret [options] command ...

Options:

    -f <secretdir>                - store (and retrieve) configuration from this directory

Commands:

    secret enrol [--force] <id> <server> - create a key pair, and send the public key to the given Secret server.
    secret share <peerID> [file]         - share file (or stdin) to the given peer.
    secret ls                            - list messages waiting for you
    secret get <msgid>                   - print the message with the given ID to stdout.
