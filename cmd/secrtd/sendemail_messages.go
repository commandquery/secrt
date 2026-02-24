package main

const activationEmail = `Hi! Thanks for trying secrt.io.

secrt.io is a command line tool for securely sharing digital secrets with coworkers,
friends, and people who need to know.

To activate your account, please copy and paste this command into your command line:

	secrt activate "{{.Token}}" {{.Code}}

You can find out more about secrt.io by visiting our web site: https://secrt.io/

Thanks for trying secrt.io!
- The Secrt Team
`

const inviteEmail = `Hi!

secrt.io is a command line tool for securely sharing digital secrets with coworkers, friends, and people who need to know.

You've been invited to use secrt by {{.Sender}}.

To accept the invite and start sharing digital secrets, simply download the secrt binary from https://secrt.io/ and type:

	secrt enrol {{.Recipient}}

Thanks for trying secrt.io!
- The Secrt Team
`
