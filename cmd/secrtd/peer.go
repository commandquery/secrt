package main

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

// Peer is a user who's enrolled in a server instance.
// Different peers can have the same alias if they're in different servers.
type Peer struct {
	Server    uuid.UUID
	Peer      uuid.UUID
	Alias     string
	PublicKey []byte
}

func prefixFromHex(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err
}

func uuidBoundsFromPrefix(prefix uint32) (lower, upper uuid.UUID) {
	binary.BigEndian.PutUint32(lower[:4], prefix)
	binary.BigEndian.PutUint32(upper[:4], prefix+1)
	return lower, upper
}

func (server *SecretServer) handleGetPeer(r *http.Request, req *secrt.PeerRequest) (*secrt.PeerResponse, error) {

	if _, err := server.Authenticate(r); err != nil {
		return nil, err
	}

	peer, ok := server.GetPeer(req.Alias)
	if !ok {
		return nil, jtp.NotFoundError(fmt.Errorf("peer not found"))
	}

	return &secrt.PeerResponse{
		Alias:        req.Alias,
		BoxPublicKey: peer.PublicKey,
	}, nil
}
