package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

//go:embed ui/activate.html
var activatePage string

// activation returns a token which is used in authentication.
func (server *SecretServer) handlePostActivate(r *http.Request, req *secrt.ActivationRequest) (*secrt.ActivationResponse, error) {
	token, err := base64.RawURLEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("invalid token: %w", err))
	}

	var peer uuid.UUID
	var alias string
	var publicKey []byte

	row := PGXPool.QueryRow(r.Context(), "select _peer, _alias, _public_key from secrt.activate($1, $2)", token, req.Code)
	err = row.Scan(&peer, &alias, &publicKey)
	if err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("unable to retrieve token: %w", err))
	}

	authToken := AuthenticationToken{
		Issued:    time.Now().Unix(),
		Peer:      peer,
		Alias:     alias,
		PublicKey: publicKey,
	}

	authTokenBytes, err := json.Marshal(&authToken)
	if err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("unable to serialize token: %w", err))
	}

	authTokenCipher, err := server.EncryptSecret(authTokenBytes)
	if err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("unable to encrypt token: %w", err))
	}

	return &secrt.ActivationResponse{
		Message: "Welcome to secrt!",
		Token:   authTokenCipher,
	}, nil
}

// Display the activation web page.
func handleGetActivate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(activatePage))
}
