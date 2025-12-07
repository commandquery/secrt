package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

// MessageSizeLimit limits the size of individual messages.
const MessageSizeLimit = 10 * 1024 * 1024

// MessageInboxLimit limits the number of messages per user
// If exceeded, the oldest message is silently deleted.
const MessageInboxLimit = 10

// MessageExpiry limits how long a message is stored.
const MessageExpiry time.Duration = 24 * time.Hour

type SecretServer struct {
	lock       sync.Mutex
	Path       string           `json:"-"` // where this config was loaded
	PrivateKey []byte           `json:"privateKey"`
	PublicKey  []byte           `json:"publicKey"`
	Users      map[string]*User `json:"users"`
	Skew       int64            `json:"skew"` // allowable time skew for authentication nonce, seconds.
}

type Message struct {
	ID        uuid.UUID
	Sender    *User
	Timestamp time.Time
	Data      []byte
}

type User struct {
	lock      sync.Mutex
	UserID    string     `json:"userId"`
	PublicKey []byte     `json:"publicKey"`
	Messages  []*Message `json:"-"` // messages are transient, at least for now.
}

func MustDecode(b64 string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}

	return bytes
}

// ejectMessages ejects old messages. User MUST be locked before calling ejectMessages.
func (user *User) ejectMessages() {
	cutoff := time.Now().Add(-MessageExpiry)
	for index, message := range user.Messages {
		if message.Timestamp.After(cutoff) {
			// messages are stored in order.
			if index > 0 {
				user.Messages = user.Messages[index:]
			}
			return
		}
	}

	// All messages expired (or slice was empty)
	user.Messages = nil
}

// FIXME: TESTING ONLY - MUST GENERATE NEW KEYS!!!
// Returns a server config for testing.
func NewSecretServer(path string) *SecretServer {
	server := &SecretServer{
		Path:       path,
		PrivateKey: MustDecode("62m1YMAMBmI44AF0yU/7uzUNr3cChzZ3RWGAxFGGLDY="),
		PublicKey:  MustDecode("h7KZ/za0dmkkHutPKESV+C1svNk0ZYbCNfGgYuIA3lg="),
		Skew:       30,
		Users:      make(map[string]*User),
	}

	return server
}

func Load(path string) (*SecretServer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	secretServer := &SecretServer{
		Path: path,
	}

	err = json.NewDecoder(f).Decode(secretServer)
	if err != nil {
		return nil, err
	}

	return secretServer, nil
}

func (server *SecretServer) Save() error {
	// FIXME: write-and-replace rather than overwrite.
	f, err := os.OpenFile(server.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(server)
}

func (server *SecretServer) GetUser(uid string) (user *User, ok bool) {
	user, ok = server.Users[uid]
	return
}

func (server *SecretServer) Authenticate(r *http.Request) (*User, error) {
	sig := r.Header.Get("Signature")
	if sig == "" {
		return nil, errors.New("missing signature header")
	}

	log.Println("server: received signature: " + sig)
	// Signature is base64-encoded JSON
	js, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	var signature Signature
	if err = json.Unmarshal(js, &signature); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	ciphertext := signature.Sig

	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`.", ciphertext[0])
	}

	peer, ok := server.Users[signature.Peer]
	if !ok {
		return nil, fmt.Errorf("unknown peer %q", signature.Peer)
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	plaintext, ok := box.Open(out, ciphertext[25:], &nonce, To32(peer.PublicKey), To32(server.PrivateKey))
	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peer.UserID)
	}

	timestamp, err := strconv.ParseInt(string(plaintext), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	// check time window
	now := time.Now().Unix()
	diff := now - timestamp
	if diff > server.Skew || diff < -server.Skew {
		return nil, errors.New("signature expired")
	}

	return peer, nil
}

func cmdServer() error {
	mux := http.NewServeMux()

	server, err := Load("server.json")
	if errors.Is(err, os.ErrNotExist) {
		server = NewSecretServer("server.json")
		if err = server.Save(); err != nil {
			exit(1, fmt.Errorf("failed to init server: %w", err))
		}
	}

	mux.HandleFunc("POST /enrol/{peer}", server.handleEnrol)
	mux.HandleFunc("POST /send/{recipient}", server.handleSend)
	mux.HandleFunc("GET /inbox", server.handleInbox)
	mux.HandleFunc("GET /publickey/{peer}", server.handlePublicKey)
	mux.HandleFunc("GET /message/{id}", server.handleMessage)

	log.Println("listening on :8080")
	return http.ListenAndServe(":8080", mux)
}

// Enrollment accepts a key from the client, and returns the server key.
func (server *SecretServer) handleEnrol(w http.ResponseWriter, r *http.Request) {
	server.lock.Lock()
	defer server.lock.Unlock()

	userID := r.PathValue("peer")
	log.Println("received enrol request for user:", userID)

	peerKey, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("unable to read peer key:", err)
		http.Error(w, "unable to read peer key", http.StatusBadRequest)
		return
	}

	log.Println("received peer key", base64.StdEncoding.EncodeToString(peerKey))

	// never override an existing user's public key.
	existingUser, ok := server.GetUser(userID)
	if ok {
		// user can re-enrol with their existing public key.
		if bytes.Equal(existingUser.PublicKey, peerKey) {
			_, _ = w.Write(server.PublicKey)
			return
		}

		// a new public key requires a reauthentication process which we don't have now.
		http.Error(w, "cannot replace existing peer", http.StatusForbidden)
		return
	}

	user := &User{
		UserID:    userID,
		PublicKey: peerKey,
	}

	server.Users[userID] = user

	if err = server.Save(); err != nil {
		http.Error(w, "unable to enrol user", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/octet-stream")
	_, _ = w.Write(server.PublicKey)
}

func (server *SecretServer) handleSend(w http.ResponseWriter, r *http.Request) {
	sender, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	recipientID := r.PathValue("recipient")
	if recipientID == "" {
		http.Error(w, "missing recipient", http.StatusBadRequest)
		return
	}

	recipient, ok := server.GetUser(recipientID)
	if !ok {
		http.Error(w, "unknown user", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MessageSizeLimit)
	messageBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newMessage := &Message{
		ID:        uuid.New(),
		Sender:    sender,
		Timestamp: time.Now(),
		Data:      messageBytes,
	}

	recipient.lock.Lock()
	defer recipient.lock.Unlock()

	recipient.ejectMessages()

	if len(recipient.Messages) == MessageInboxLimit {
		recipient.Messages = recipient.Messages[1:]
	}

	recipient.Messages = append(recipient.Messages, newMessage)
}

func (server *SecretServer) handleInbox(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Don't show old messages
	peer.ejectMessages()

	// 204 just means there's nothing here. No messages!
	if len(peer.Messages) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	inbox := &Inbox{
		Messages: make([]InboxMessage, 0, len(peer.Messages)),
	}

	for _, msg := range peer.Messages {
		inbox.Messages = append(inbox.Messages, InboxMessage{
			ID:        msg.ID,
			Sender:    msg.Sender.UserID,
			Timestamp: msg.Timestamp.Unix(),
			Size:      len(msg.Data),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(inbox)
}

func (server *SecretServer) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if _, err := server.Authenticate(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	peerID := r.PathValue("peer")
	if peerID == "" {
		http.Error(w, "missing peer", http.StatusBadRequest)
	}

	user, ok := server.GetUser(peerID)
	if !ok {
		http.Error(w, "unknown peer", http.StatusNotFound)
	}

	w.Header().Add("Content-Type", "application/octet-stream")
	_, _ = w.Write(user.PublicKey)
}

func (server *SecretServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		http.Error(w, "invalid message id", http.StatusBadRequest)
	}

	id = strings.ToLower(id)
	var selected *Message

	for _, msg := range peer.Messages {
		if strings.HasPrefix(msg.ID.String(), id) {
			if selected != nil {
				http.Error(w, "ambiguous message id", http.StatusConflict)
				return
			}

			selected = msg
		}
	}

	if selected == nil {
		http.Error(w, "unknown message", http.StatusNotFound)
		return
	}

	w.Header().Add("Peer-ID", selected.Sender.UserID)
	w.Header().Add("Content-Type", "application/octet-stream")
	_, _ = w.Write(selected.Data)
}
