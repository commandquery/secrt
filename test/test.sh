#!/bin/bash
#
# TODO
# Write assertions for the test results!

# Make sure cgo doesn't get used.
export CGO_ENABLED=0

# PG settings for testing
export PGDATABASE=st
export PGSSLMODE=disable

# These are TEST TOKENS for a sandbox server and are therefore not sensitive.
# They let us attempt to send via SMTP but the emails will never be delivered.
export SECRT_SMTP_USERNAME=02a67563-30d0-468d-a243-840d14cd2099
export SECRT_SMTP_PASSWORD=02a67563-30d0-468d-a243-840d14cd2099

# By default we don't test SMTP because it's too slow.
export SECRT_SMTP_DISABLE=true

# Use a small challenge size to keep tests snappy.
# Default challenge size is 24.
# Incrementing the challenge size by one, doubles the average time it takes to solve.
export SECRT_CHALLENGE_SIZE=10
export SECRT_ENROL_ACTION=file
export SECRT_ENROL_FILE=token.txt

# Print debugging information (or not)
#export SECRT_DEBUG_JSON=true
export SECRT_PRIVACY_MESSAGE=false
export SECRT_TELEMETRY=false

set -e

dropdb $PGDATABASE
createdb $PGDATABASE

# Enrol a user via the token file mechanism.
# Server puts the tokens and codes into a file that we use to activate the enrolment.
# usage: enrol file.json peerid store
enrol() {
  secrt -c $1 enrol ${3:+--store=$3} $2 http://localhost:8080/
  read -r token code < <(tail -1 $SECRT_ENROL_FILE)
  secrt -c $1 activate "$token" "$code"
}

cleanup() {
  kill "$SECRTD" 2>/dev/null
  wait "$SECRTD" 2>/dev/null
}
trap cleanup EXIT

# Build the binaries into the current directory and
# make them accessible to the rest of the script.
PATH=.:$PATH
go build -ldflags "-X main.BuildID=test.sh" -o secrt ../cmd/secrt
go build  -ldflags "-X main.BuildID=test.sh" -o secrtd ../cmd/secrtd
go test ..

rm -rf stores/* $SECRT_ENROL_FILE
mkdir -p stores

secrtd add http://localhost:8080

secrtd &
SECRTD=$!

for _ in {1..30}; do nc -z localhost 8080 && break || sleep 0.1; done

#
# Enrol alice and bob
#
echo "--- secrt enrol"
enrol stores/alice alice@example.com clear
enrol stores/bob bob@example.com clear

#
# Send a message from alice to bob
#
echo "--- secrt send"
MSGID=$(echo "hello" | secrt -c stores/alice send -d "hello file" bob@example.com)
echo "message ID: $MSGID"

#
# Retrieve the message
#
echo "--- secrt get"
MSG=$(secrt -c stores/bob get $MSGID)
echo "get message $MSG"
if [ "$MSG" != "hello" ]; then
  echo "expected hello" 1>&2
  exit 1
fi

#
# Test that sending to an unknown peer fails
# This caused a panic in an early SECRTD version!
# If the SECRTD panics now, subsequent tests will fail.
#
echo "--- send to unknown peer"
if echo "hello" | secrt -c stores/alice send nobody@example.com 2>/dev/null; then
  echo "secrt send to nobody@example.com should have failed!" 2>&1
  exit 1
fi

#
# Use the short ID - must do a ls first to get it into cache
#
echo "--- secrt get short"
SHORTID=${MSGID:0:8}
echo "get message $SHORTID"
MSG=$(secrt -c stores/bob get $SHORTID)
if [ "$MSG" != "hello" ]; then
  echo "expected hello" 1>&2
  exit 1
fi

#
# Send a named file from bob to alice.
#
echo "--- secrt send (named)"
MSGID=$(secrt -c stores/bob send ./TEST.md alice@example.com)

#
# Test that acceptNewPeers=false doesn't break ls.
# Enrol Charlie, but disable acceptPeers.
#
echo "--- secrt ls (acceptPeers=false)"
enrol stores/charlie charlie@example.com clear
secrt -c stores/charlie set acceptPeers=false
ALICEMSG=$(echo "hello" | secrt -c stores/alice send charlie@example.com)
secrt -c stores/charlie ls

#
# Since Charlie doesn't accept peers, she shouldn't be able to send to alice.
#
echo "--- secrt send (acceptPeers=false)"
if secrt -c stores/charlie send ./TEST.md alice@example.com 2> /dev/null; then
  echo "secrt send should have failed!" 1>&2
  exit 1
fi

#
# Since Charlie doesn't accept peers, she shouldn't be able to receive from alice.
#
echo "--- secrt get (acceptPeers=false)"
if secrt -c stores/charlie get $ALICEMSG 2> /dev/null; then
  echo "secrt get should have failed!" 1>&2
  exit 1
fi



#
# Test different versions of "ls"
#
echo "--- secrt ls (variations)"
secrt -c stores/alice ls
secrt -c stores/alice ls --json


#
# Tests that secrt rm works.
#
echo "--- secrt rm"
MSGID=$(echo "msg#2" | secrt -c stores/alice send bob@example.com)
secrt -c stores/bob ls
secrt -c stores/bob rm $MSGID

if secrt -c stores/bob get $MSGID 2> /dev/null; then
  echo "secrt get should have failed (message has been deleted!)"
  exit 1
fi

#
# Bad message ID
#
if secrt -c stores/bob rm xxxxxxxx 2> /dev/null; then
  echo "secrt rm should have failed"
  exit 1
fi

#
# Valid but missing message ID
#
if secrt -c stores/bob rm 91743420-7FFA-491F-B64B-02B88873B8F7 2> /dev/null; then
  echo "secrt rm should have failed"
  exit 1
fi

secrt -c stores/bob ls

#
# Test that "-o name" works.
#
echo "--- secret get -o"
rm -f OUTPUT.md
MSGID=$(secrt -c stores/bob send ./TEST.md alice@example.com)
secrt -c stores/alice get -o OUTPUT.md $MSGID
if ! diff OUTPUT.md TEST.md > /dev/null; then
  echo "OUTPUT.md and TEST.md are different!" 1>&2
  exit 1
fi

#
# Secrt peer ls
#
echo "--- secret peer ls"
secrt -c stores/alice peer ls

#
# Secrt peer rm
#
echo "--- secret peer rm"
secrt -c stores/alice peer rm charlie@example.com
secrt -c stores/alice peer ls

#
# Secrt peer add
#
echo "--- secret peer add"
secrt -c stores/alice peer add charlie@example.com
secrt -c stores/alice peer ls

#
# Test platform vault create
#
echo "--- enrol with platform vault"
enrol stores/denise denise@example.com platform

#
# Test platform vault access
#
echo "--- send with platform vault"
MSGID=$(echo "platform vault" | secrt -c stores/denise send alice@example.com)
MSG=$(secrt -c stores/alice get $MSGID)

#
# Test the default vault type is "platform"
#
echo "--- default vault type"
enrol stores/ernie ernie@example.com
if ! jq -e '.endpoints[0].vaults | map(select(.vaultType == "platform")) | length == 1' stores/ernie/secrt.json > /dev/null; then
  echo "unexpected vault type in stores/ernie/secrt.json, expected default to be 'platform'"
  exit 1
fi

#
# Send to multiple users
#
echo "--- secrt send multiple"
secrt -c stores/alice send ./TEST.md bob@example.com charlie@example.com denise@example.com ernie@example.com

#
# Send to multiple users (with an error)
#
echo "--- secrt send multiple - error check"
if secrt -c stores/alice send ./TEST.md bob@example.com charlie@example.com denise@example.com error@example.com 2> /dev/null; then
  echo "secrt send to error@example.com should have failed!" 2>&1
  exit 1
fi

#
# Test sending an invite
#
echo "--- secrt invite user"
secrt -c stores/alice invite fred@example.com

#
# Invite someone who is already enrolled
#
echo "--- secrt invite enrolled"
if secrt -c stores/alice invite bob@example.com; then
  echo "secrt invite should have failed!" 2>&1
  exit 1
fi

#
# Attempt to double enrol without --force
#
echo "--- secrt double enrol fail test"
enrol stores/guy guy@example.com clear
if secrt -c stores/guy enrol guy@example.com http://localhost:8080/ 2> /dev/null; then
  echo "secrt enrol should have failed!" 2>&1
  exit 1
fi

#
# Attempt to enrol on same SECRTD with different peer ID
#
echo "--- secrt same SECRTD different peer"
enrol stores/guy harry@example.com clear

#
# Test that the default endpoint changes
#
echo "--- use different enrolment"
echo "hello" | secrt -c stores/guy send alice@example.com
secrt -c stores/alice ls

#
# Attempt to double enrol with --force
# FIXME: this won't work until we have a reenrolment flow on the SECRTD side
#
#echo "--- secrt double enrol --force"
#secrt -c stores/guy enrol --force guy@example.com http://localhost:8080/

#
# Test "secrt run" - with an environment
#
enrol stores/joe joe@example.com clear
ENVID=$(echo "SECRT_ENV=true" | secrt -c stores/joe send joe@example.com)
secrt -c stores/joe run -env $ENVID env

#
# Test "secrt run" - with stdin
#
STDINID=$(echo "hello, world" | secrt -c stores/joe send joe@example.com)
secrt -c stores/joe run -stdin $STDINID cat

#
# Test "secrt run" - with stdin
#
secrt -c stores/joe run -env $ENVID -stdin $STDINID sh -c "env; cat"