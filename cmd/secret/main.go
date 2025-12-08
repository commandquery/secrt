package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/nacl/box"
)

//go:embed README.md
var readme string

func usage(msg ...any) {

	_, _ = os.Stderr.WriteString(readme)
	fmt.Println()

	if len(msg) > 0 {
		fmt.Println()
		fmt.Println(msg...)
		fmt.Println()
	}

	os.Exit(1)
}

func exit(code int, err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(code)
}

func cmdEnrol(config *Client, args []string) error {

	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	force := flags.Bool("force", false, "force overwrite")
	if err := flags.Parse(args); err != nil {
		usage("secret init [--force] user@domain https://server/")
	}

	// If only one arg and the config came from disk, don't overwrite it.
	if config.Stored && !*force {
		exit(1, fmt.Errorf("a secret configuration already exists; use --force to overwrite it"))
	}

	args = flags.Args()
	if len(args) != 2 {
		usage("secret init [--force] user@domain https://server/")
	}

	config.DefaultPeerID = args[0]
	if err := config.AddServer(args[1]); err != nil {
		exit(1, fmt.Errorf("unable to initialise keys: %w", err))
	}

	return config.Save()
}

func cmdKey(server *Endpoint) error {
	b64 := base64.StdEncoding.EncodeToString(server.PublicKey)
	fmt.Println(b64)
	return nil
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

func encrypt(endpoint *Endpoint, plaintext []byte, peerKey []byte) ([]byte, error) {
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		exit(2, err)
	}

	// Prefix the message with a version number of the ciphertext message.
	// Current version is zero.
	var ciphertext = []byte{0}

	// Append the nonce, which is a fixed length (24 bytes).
	ciphertext = append(ciphertext, nonce[:]...)

	// Encrypt the message itself and append to the nonce + public key
	return box.Seal(ciphertext, plaintext, &nonce, To32(peerKey), To32(endpoint.PrivateKey)), nil
}

func decrypt(server *Endpoint, peerID string, ciphertext []byte) ([]byte, error) {
	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`.", ciphertext[0])
	}

	peer, err := server.GetPeer(peerID)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	out, ok := box.Open(out, ciphertext[25:], &nonce, To32(peer.PublicKey), To32(server.PrivateKey))

	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peerID)
	}

	return out, nil
}

// Generate a key pair. This is mostly for seting up a server
func cmdGenKey() {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Public:  %s\n", base64.StdEncoding.EncodeToString(pub[:]))
	fmt.Printf("Private: %s\n", base64.StdEncoding.EncodeToString(priv[:]))
}

func main() {

	if err := initConfig(); err != nil {
		exit(1, err)
	}

	args := os.Args

	if len(args) == 1 {
		// --help, or anything else.
		usage()
	}

	if args[1] == "server" {
		exit(0, cmdServer())
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
		fmt.Fprintf(os.Stderr, "you need to enrol before you can use `secret`:\n", command)
		fmt.Fprintf(os.Stderr, "    secret enrol email@example.com https://secret.example.com/\n")
		os.Exit(1)
	}

	// we only support the default server for now.

	switch command {
	case "enrol":
		err = cmdEnrol(config, args)

	case "key":
		server := config.Servers[0]
		err = cmdKey(server)

	case "send":
		server := config.Servers[0]
		err = cmdSend(server, args)
		config.Save() // TODO: should only happen if a peer was added. FIXME: no error check.

	case "ls":
		server := config.Servers[0]
		err = cmdLs(server, args)

	case "get":
		server := config.Servers[0]
		err = cmdGet(server, args)
		config.Save() // TODO: should only happen if a peer was added. FIXME: no error check.

	case "genkey":
		cmdGenKey()

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
