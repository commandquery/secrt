package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

func usage(msg ...any) {
	fmt.Fprintln(os.Stderr,
		`Secret is a simple command for exchanging sensitive data over public networks
such as email or Discord, and saving it to your home directory.

General format:

  secret [options] command ...

Options:
  -f <secretdir>               - store (and retrieve) configuration from this directory

General Commands:
  init [--force] <id>          - create (or replace) your public key and your ID.
  key [-n]                     - show your public key, so you can send it to your peeps. -n don't include help text.
  add <peerID> <token>         - add a public key <token> sent by a friend whose ID is <peerID>
  send <peerID> [file]         - encrypt file or stdin for friend <peerID> and print it to stdout
  decrypt <peerID> [file]      - decrypt stdin from <peerID> and print it to stdout

File Commands:
  save <peerID> <name> [file]  - save a file sent by <peerID>, using the given file name
  import <name> [file]         - import the operating system file into your secrets, encrypting it as we go
  cat <name>                   - print the decrypted contents of the previously saved file <name>
  rm <name>                    - Delete the secret called <name>. Forever!
  ls                           - List files that have been previously saved.`)

	if len(msg) > 0 {
		fmt.Println()
		fmt.Println(msg)
		fmt.Println()
	}

	os.Exit(1)
}

func exit(code int, err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(code)
}

func getSecretFile(config *Configuration) (string, error) {
	return config.Store + "/keys", nil
}

// Convert the obejct to JSON but display as a base64 string.
// This makes the object much easier to copy and paste, and also makes
// it a bit more mysterious...
func format(prefix string, bytes []byte) error {
	b64 := []byte(base64.StdEncoding.EncodeToString(bytes))

	// Try to make the output object square, but no more than 80
	// columns.
	width := int(math.Sqrt(float64(len(b64)))) * 2
	if width > 80 {
		width = 80
	}

	// Leave space around the box to make it easy to copy
	output := []byte(prefix)

	for index, value := range b64 {
		if index%width == 0 {
			output = append(output, '\n')
			output = append(output, []byte(prefix)...)
		}
		output = append(output, value)
	}

	output = append(output, '\n')

	_, err := os.Stdout.Write(output)
	return err
}

// Take a string created by the format() function and turn it back into JSON.
// Trims any whitespace that might have been added. Removes leading "// " and
// any sequence of "\n// " so that comments from code can be pasted as well.
func unformat(b64 []byte) ([]byte, error) {
	s64 := string(b64)

	// Strip off commented-out code.
	if len(s64) >= 3 && s64[:3] == "// " {
		s64 = s64[3:]
	}

	s64 = strings.ReplaceAll(s64, "\n// ", "")
	s64 = strings.ReplaceAll(s64, " ", "")
	s64 = strings.TrimSpace(s64)

	return base64.StdEncoding.DecodeString(s64)
}

func getPublicKey(config *Configuration, prefix string) (string, error) {
	entry := Peer{Version: 0, PeerID: config.UserID, PublicKey: config.PublicKey}

	bytes, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}

	b64 := base64.StdEncoding.EncodeToString(bytes)

	return b64, nil
}

func cmdInit(config *Configuration, args []string) error {

	if len(args) < 1 || len(args) > 2 {
		usage()
	}

	// If only one arg and the config came from disk, don't overwrite it.
	if config.Stored && len(args) == 1 {
		exit(1, fmt.Errorf("A secret already exists. Use --force to overwrite it."))
	}

	// If there are two args, the first one must be --force
	if len(args) == 2 && args[0] != "--force" {
		usage()
	}

	if err := config.InitKeys(); err != nil {
		exit(1, fmt.Errorf("unable to initialise keys: %w", err))
	}
	config.UserID = args[len(args)-1]

	return config.Save()
}

func cmdKey(config *Configuration, args []string) error {

	decorate := true

	if len(args) > 0 && args[0] == "-n" {
		decorate = false
	}

	b64, err := getPublicKey(config, "  ")

	if decorate {
		fmt.Printf("secret add %s %s\n", config.UserID, b64)
	} else {
		fmt.Println(b64)
	}

	return err
}

func cmdAdd(config *Configuration, args []string) error {
	if len(args) != 2 {
		usage("add <peer> <token>")
	}

	peerId := strings.ToLower(args[0])

	bytes, err := unformat([]byte(args[1]))
	if err != nil {
		return err
	}

	var entry Peer
	err = json.Unmarshal(bytes, &entry)
	if err != nil {
		return err
	}

	if strings.ToLower(entry.PeerID) != peerId {
		exit(2, fmt.Errorf("The public key belongs to %s, not %s", entry.PeerID, peerId))
	}

	if config.Peers == nil {
		config.Peers = make(map[string]Peer)
	}

	config.Peers[peerId] = entry
	return config.Save()
}

// readInput reads a byte slice from a file or stdin.
// If the filename is "-" or if it's outside the array, read from stdin.
// Otherwise, read from the file.
//
// Args is the list of arguments, and arg is the zero-value index of the argument we
// are looking for.
func readInput(args []string, arg int) ([]byte, error) {
	// Use a filename, or just stdin?
	var reader io.Reader
	if len(args) > arg {
		file, err := os.Open(args[arg])
		if err != nil {
			return nil, err
		}

		defer file.Close()
		reader = file
	} else {
		reader = os.Stdin
	}

	return io.ReadAll(reader)
}

func encrypt(config *Configuration, plaintext []byte, peerID string) ([]byte, error) {
	peer, err := config.GetPeer(peerID)
	if err != nil {
		return nil, err
	}

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		exit(2, err)
	}

	// Prefix the message with a version number of the ciphertext message.
	// This is so we can fail if we receive a different version.
	// Current version is zero.
	var ciphertext = []byte{0}

	// Append the nonce, which is a fixed length (24 bytes).
	ciphertext = append(ciphertext, nonce[:]...)

	// Encrypt the message itself and append to the nonce + public key
	return box.Seal(ciphertext, plaintext, &nonce, To32(peer.PublicKey), To32(config.PrivateKey)), nil
}

// Send stdin to stdout after being encrypted with the given public key.
// arg[0] = receipient
// arg[1] = filename (optional)
func cmdSend(config *Configuration, args []string) error {
	if len(args) < 1 {
		usage()
	}

	plaintext, err := readInput(args, 1)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(config, plaintext, args[0])
	if err != nil {
		return err
	}

	return format("  ", ciphertext)
}

func decrypt64(config *Configuration, peerID string, text64 []byte) ([]byte, error) {
	ciphertext, err := unformat(text64)
	if err != nil {
		return nil, err
	}

	return decrypt(config, peerID, ciphertext)
}

func decrypt(config *Configuration, peerID string, ciphertext []byte) ([]byte, error) {
	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`.", ciphertext[0])
	}

	peer, err := config.GetPeer(peerID)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	out, ok := box.Open(out, ciphertext[25:], &nonce, To32(peer.PublicKey), To32(config.PrivateKey))

	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peerID)
	}

	return out, nil
}

func cmdDecrypt(config *Configuration, args []string) error {
	if len(args) < 1 || len(args) > 3 {
		usage()
	}

	ciphertext, err := readInput(args, 1)
	if err != nil {
		return err
	}

	ciphertext, err = unformat(ciphertext)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(config, args[0], ciphertext)

	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(plaintext)
	return err
}

// secret save <peerID> <name> [file]
//
// Saves the secret in ~/.config/secret/files.
// This can be used by clients (eg, klog) to read the secret.
func cmdSave(config *Configuration, args []string) error {
	if len(args) < 2 {
		usage()
	}

	text64, err := readInput(args, 2)
	if err != nil {
		return err
	}

	// In order to be able to decrypt the file later without having the sender's
	// public key, we need to re-encrypt it anonymously.
	plaintext, err := decrypt64(config, args[0], text64)
	if err != nil {
		return err
	}

	return config.SaveFile(args[1], plaintext)
}

// secret get <name>
// Accesses a secret that's been stored in the files section. It's encrypted
// using the user's private key.
func cmdCat(config *Configuration, args []string) error {
	if len(args) != 1 {
		usage()
	}

	plaintext, err := config.GetFile(args[0])
	if err != nil {
		return fmt.Errorf("unable to show secret %s", args[0])
	}

	_, err = os.Stdout.Write(plaintext)
	return err
}

func cmdRm(config *Configuration, args []string) error {
	if len(args) != 1 {
		usage()
	}

	loadPath, err := config.GetFileStore(args[0])
	if err != nil {
		return err
	}

	err = os.Remove(loadPath)
	if err != nil {
		return fmt.Errorf("unable to remove secret %s: %w", args[0], err)
	}

	// Remove the file's metadata
	delete(config.Files, args[0])
	return config.Save()
}

func cmdLs(config *Configuration, args []string) error {
	for name := range config.Files {
		fmt.Println(name)
	}
	return nil
}

// Import an unencrypted file into Secret. This encrypts the file with your public key
// before storing it. It's used to e.g. import a TLS certificate directly from a file.
//
// secret import secret-filename [from-filename]
func cmdImport(config *Configuration, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		usage()
	}

	// Load the file using the provided filename, or stdin.
	plaintext, err := readInput(args, 1)
	if err != nil {
		return err
	}

	return config.SaveFile(args[0], plaintext)
}

func main() {
	args := os.Args

	if len(args) == 1 {
		// --help, or anything else.
		usage()
	}

	var store string
	var err error

	// -f option allows us to specify a different configuration folder.
	if args[1] == "-f" {
		if len(args) < 3 {
			usage()
		}

		store = args[2]
		args = args[2:]
	} else {
		store, err = GetSecretStore()
		if err != nil {
			exit(1, err)
		}
	}

	config, err := LoadSecretConfiguration(store)
	if err != nil {
		exit(1, err)
	}

	if config.Version != ConfigVersion {
		panic(fmt.Errorf("unexpected config version: %d", config.Version))
	}

	command := args[1]
	args = args[2:]

	if !config.Stored && command != "init" {
		fmt.Fprintf(os.Stderr, "you need to initialise your keys before you can use `secret %s` using:\n", command)
		fmt.Fprintf(os.Stderr, "    secret init email@example.com\n")
		os.Exit(1)
	}

	switch command {
	case "init":
		err = cmdInit(config, args)
	case "key":
		err = cmdKey(config, args)
	case "add":
		err = cmdAdd(config, args)
	case "send":
		err = cmdSend(config, args)
	case "save":
		err = cmdSave(config, args)
	case "cat":
		err = cmdCat(config, args)
	case "rm":
		err = cmdRm(config, args)
	case "ls":
		err = cmdLs(config, args)
	case "decrypt":
		err = cmdDecrypt(config, args)
	case "import":
		err = cmdImport(config, args)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
	}

	if err == nil {
		os.Exit(0)
	}

	exit(1, err)
}
