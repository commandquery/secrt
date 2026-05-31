package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
)

var ErrExistingPeer error = errors.New("peer already exists")
var ErrAmbiguousMessageID error = errors.New("ambiguous message MessageID")
var ErrUnknownMessageID error = errors.New("unknown message MessageID")

type SecretServer struct {
	Server         uuid.UUID
	Hostname       string
	BoxSecretKey   []byte
	BoxPrivateKey  []byte
	BoxPublicKey   []byte
	SignPrivateKey []byte
	SignPublicKey  []byte
}

type AuthenticationToken struct {
	Issued    int64     `json:"issued"`
	Peer      uuid.UUID `json:"peer"`
	Alias     string    `json:"alias"`
	PublicKey []byte    `json:"publicKey"`
}

type Session struct {
	Peer      *Peer  // The peer associated with this session
	PublicKey []byte // The public key used to authenticate with this session.
}

// NewSecretServer returns a new SecretServer with a unique private and public key.
func NewSecretServer(hostname string) *SecretServer {
	boxPublicKey, boxPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	signPublicKey, signPrivateKey, err := sign.GenerateKey(rand.Reader)
	var boxSecretKey [32]byte
	if _, err := rand.Read(boxSecretKey[:]); err != nil {
		panic(err)
	}

	server := &SecretServer{
		Server:         uuid.New(),
		Hostname:       hostname,
		BoxSecretKey:   boxSecretKey[:],
		BoxPrivateKey:  boxPrivateKey[:],
		BoxPublicKey:   boxPublicKey[:],
		SignPrivateKey: signPrivateKey[:],
		SignPublicKey:  signPublicKey[:],
	}

	return server
}

// GetSecretServer returns a secret server based on the given hostname.
func GetSecretServer(hostname string) (*SecretServer, error) {
	ctx := context.Background()
	row := PGXPool.QueryRow(ctx, "select server, secret_box_key, private_box_key, public_box_key, private_sign_key, public_sign_key from secrt.hostname join secrt.server using (server) where hostname=$1", hostname)

	server := SecretServer{
		Hostname: hostname,
	}
	err := row.Scan(&server.Server, &server.BoxSecretKey, &server.BoxPrivateKey, &server.BoxPublicKey, &server.SignPrivateKey, &server.SignPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to find server %s: %w", hostname, err)
	}

	return &server, nil
}

// EncryptSecret encrypts an object with the server's secret key. This is used for authentication tokens.
func (server *SecretServer) EncryptSecret(message []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], message, &nonce, secrt.To32(server.BoxSecretKey))
	return encrypted, nil
}

func (server *SecretServer) DecryptSecret(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, errors.New("ciphertext too short")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	message, ok := secretbox.Open(nil, encrypted[24:], &nonce, secrt.To32(server.BoxSecretKey))
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return message, nil
}

func (server *SecretServer) GetPeer(alias string) (*Peer, bool) {
	ctx := context.Background()

	peer := Peer{
		Server: server.Server,
		Alias:  alias,
	}

	row := PGXPool.QueryRow(ctx, "select peer, public_key from secrt.peer join secrt.key using (peer) where key.key = peer.default_key and server=$1 and alias=$2", server.Server, alias)
	err := row.Scan(&peer.Peer, &peer.DefaultPublicKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false
		}
		log.Printf("error attempting to read peer %s: %v", alias, err)
		return nil, false
	}

	return &peer, true
}

func (server *SecretServer) HasPublicKey(peer uuid.UUID, keyType string, publicKey []byte) error {
	ctx := context.Background()

	var exists bool
	row := PGXPool.QueryRow(ctx, "select true from secrt.key where peer=$1 and type=$2 and public_key=$3", peer, keyType, publicKey)
	err := row.Scan(&exists)
	if err != nil {
		return fmt.Errorf("could not find public key for peer %s: %w", peer.String(), err)
	}

	return nil
}

func (server *SecretServer) Authenticate(r *http.Request) (*Session, *jtp.HTTPError) {

	token := r.Header.Get("Authorization")
	if token == "" {
		return nil, jtp.UnauthorizedError(fmt.Errorf("missing authorization header"))
	}

	if len(token) < 8 {
		return nil, jtp.UnauthorizedError(fmt.Errorf("invalid authorization token"))
	}

	token = token[7:]

	authTokenCipher, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, jtp.UnauthorizedError(fmt.Errorf("unable to decode token: %w", err))
	}

	tokenJs, err := server.DecryptSecret(authTokenCipher)
	if err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("unable to decrypt token: %w", err))
	}

	var authToken AuthenticationToken
	if err := json.Unmarshal(tokenJs, &authToken); err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("unable to unmarshal token: %w", err))
	}

	peer, ok := server.GetPeer(authToken.Alias)
	if !ok {
		return nil, jtp.UnauthorizedError(fmt.Errorf("unknown peer %q", authToken.Alias))
	}

	err = server.HasPublicKey(peer.Peer, "box", authToken.PublicKey)
	if err != nil {
		return nil, jtp.UnauthorizedError(err)
	}

	return &Session{
		Peer:      peer,
		PublicKey: authToken.PublicKey,
	}, nil
}
