#!/bin/bash

echo "building secrtd..."
GOOS=linux GOARCH=amd64 go build  -ldflags "-X main.BuildID=build.sh" -o secrtd .

ssh secrt /etc/init.d/secrtd stop
scp secrtd secrt:/usr/local/bin
ssh secrt /etc/init.d/secrtd start
