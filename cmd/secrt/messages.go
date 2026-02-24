package main

// Just some messages.

const privacyMessage = `
Thanks for trying secrt.io!

secrt.io is a command line tool for securely sharing digital secrets with coworkers,
friends, and people who need to know.

By default, this tool sends very limited telemetry to secrt.io. For added privacy,
you can disable this with:

	secrt set telemetry=false

For convenience, the client automatically accepts public keys for new peers. For added
security, you can disable this with:

	secrt set acceptPeers=false

With acceptPeers=false, you will need to manually add peers before you can see their
secrets. To do this, use:

	secrt peer add <alias>

We hope you enjoy using secrt.io.

`
