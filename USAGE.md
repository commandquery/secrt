secrt.io: Securely exchange secrets with your peers.

`secrt` is a simple CLI command for exchanging sensitive data with your peers using
end-to-end encryption. Encrypted messages are stored temporarily on a server until
the peer picks them up.

All messages are encrypted with your private key. The server can never read your messages.

General usage:

    secrt [options] command ...

Options:

    -f <secretdir>                - store (and retrieve) configuration from this directory

Commands:

    secrt enrol [--force] <id>              - create a key pair, and record your public key at `secrt.io`.
    secrt send <peer@domain...> [files...]  - send one or more files (or stdin) to one or more peers.
    secrt ls                                - list messages waiting for you
    secrt get <msgid>                       - print the message with the given ID to stdout.
