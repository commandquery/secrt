# Secret: Securely send and store data over plaintext channels

Secret is a simple command for exchanging sensitive data over public networks
such as email, Teams or Discord, and saving it to your home directory.

General format:

secret [options] command ...

Options:
    -f <secretdir>               - store (and retrieve) configuration from this directory

General Commands:
    init [--force] <id>          - create (or replace) your public key and your ID.
    key [-n]                     - show your public key, so you can send it to your peeps. -n don't include help text.
    add <peerID> <token>         - add a public key sent by a friend whose ID is <peerID>
    send <peerID> [file]         - encrypt file or stdin for friend <peerID> and print it to stdout
    decrypt <peerID> [file]      - decrypt stdin from <peerID> and print it to stdout

File Commands:
    save <peerID> <name> [file]  - save a file sent by <peerID>, using the given file name
    import <name> [file]         - import the operating system file into your secrets, encrypting it as we go
    cat <name>                   - print the decrypted contents of the previously saved file <name>
    rm <name>                    - Delete the secret called <name>. Forever!
    ls                           - List files that have been previously saved.