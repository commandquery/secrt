# secret server design

## Server API

### Send an encrypted message

    POST https://secret.catapult.emersion.com/send/user@domain.com
    Signature: <user@domain:time>, signed by sender, base64
    
    <ciphertext>

Stores a message for up to 24 hours. A message ID is assigned by the server.

### Show Inbox

    GET https://secret.catapult.emersion.com/inbox
    Signature: <user@domain:time>, signed by sender, base64
    
    [
        {
            "from": "user@domain"
            "id": "id",
            "sent": timestamp
        }
    ]

### Public Key Access

    GET https://secret.catapult.emersion.com/publickey/user@domain.com   // returns the user's public key
    Signature: <user@domain:time>, signed by sender, base64

client needs the public key in order to be able to send a message.

### Receive message

    GET https://secret.catapult.emersion.com/receive/<id>
    Signature: <user@domain:time>, signed by sender, base64

    Response:
    Signed-By: user@domain
    Signing-Key: base64bytes

    <ciphertext> 

### Notes

* user ID is always an email address

## Client Commands

### secret init

    secret init <email>

creates a private key for the current user and stores it.

### secret key

    secret key

prints the current user's public key, used to configure the server.

### secret send

    secret send <peer> <name> [file]

sends the file to a peer with the given name (or stdin):

* downloads the peer's key
* encrypts with private key
* and POSTs to the server.

### secret ls

    secret ls

lists all messages on the server for you, with their ID

### secret read

    secret read <id> [-o file]

reads a message:

* downloads the message
* authenticates it
* decrypts it
* prints it / writes to file.

