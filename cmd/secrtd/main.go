package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

// Temporary command to create a server.
func addServerCmd(hostname string) error {

	if !strings.HasPrefix(hostname, "http") {
		return fmt.Errorf("hostname must start with http:// or https://")
	}

	if strings.HasSuffix(hostname, "/") {
		hostname = hostname[:len(hostname)-1]
	}

	server := NewSecretServer(hostname)

	ctx := context.Background()

	_, err := PGXPool.Exec(ctx, "insert into secrt.server (server, secret_box_key, private_box_key, public_box_key, private_sign_key, public_sign_key) values ($1, $2, $3, $4, $5, $6)",
		server.Server, server.BoxSecretKey, server.BoxPrivateKey, server.BoxPublicKey, server.SignPrivateKey, server.SignPublicKey)
	if err != nil {
		return fmt.Errorf("unable to add server: %w", err)
	}

	_, err = PGXPool.Exec(ctx, "insert into secrt.hostname (hostname, server) values ($1, $2)",
		hostname, server.Server)
	if err != nil {
		return fmt.Errorf("unable to add hostname: %w", err)
	}

	return nil
}

// dispatch is a simple wrapper for jtp.Handle that finds the appropriate server and calls the given function on it.
func dispatch[IN any, OUT any](method func(*SecretServer, *http.Request, *IN) (*OUT, error)) http.HandlerFunc {
	return jtp.Handle(func(w http.ResponseWriter, r *http.Request, in *IN) (*OUT, error) {
		host := GetHostname(r)
		s, err := GetSecretServer(host)
		if err != nil {
			return nil, jtp.NotFoundError(fmt.Errorf("unable to find secret server %s: %w", host, err))
		}

		return method(s, r, in)
	})
}

func GetHostname(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// StartReaper purges expired messages every minute.
func StartReaper() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		_, err := PGXPool.Exec(context.Background(), "delete from secrt.message where expires < current_timestamp")
		if err != nil {
			log.Printf("unable to purge expired messages: %v", err)
		}
	}
}

func ListenAndServe() error {
	mux := http.NewServeMux()

	pathPrefix := Config.PathPrefix

	// The server works by finding a SecretServer based on the request's hostname, and then dispatching
	// to a function on that server.
	//
	// The unusual syntax (*SecretServer).functionName is a function expression representing a method.
	// It returns a function whose first argument is the target object. The generic dispatch
	// function uses the arguments of the method to infer the types.
	//
	// This makes things really easy to code and eliminates a number of gotchas in the standard
	// library, but it takes a little getting used to.

	// Redirect secrt.io to the website.
	mux.Handle("GET /", http.RedirectHandler("https://www.secrt.io/", http.StatusMovedPermanently))

	mux.HandleFunc("POST "+pathPrefix+"enrol", dispatch((*SecretServer).handleEnrol))
	mux.HandleFunc("GET "+pathPrefix+"inbox", dispatch((*SecretServer).handleGetInbox))
	mux.HandleFunc("POST "+pathPrefix+"message", dispatch((*SecretServer).handlePostMessage))
	mux.HandleFunc("GET "+pathPrefix+"message/{id}", dispatch((*SecretServer).handleGetMessage))
	mux.HandleFunc("DELETE "+pathPrefix+"message/{id}", dispatch((*SecretServer).handleDeleteMessage))
	mux.HandleFunc("GET "+pathPrefix+"peer", dispatch((*SecretServer).handleGetPeer))
	mux.HandleFunc("POST "+pathPrefix+"invite", dispatch((*SecretServer).handleInvite))
	mux.HandleFunc("GET "+pathPrefix+"challenge", dispatch((*SecretServer).handleGetChallenge))
	mux.HandleFunc("POST "+pathPrefix+"telemetry", dispatch((*SecretServer).handlePostTelemetry))

	// POST performs the enrolment. GET displays the HTML activation page.
	mux.HandleFunc("POST "+pathPrefix+"activate", dispatch((*SecretServer).handlePostActivate))
	mux.HandleFunc("GET "+pathPrefix+"activate", handleGetActivate)

	//log.Println("listening on :8080")
	//return http.ListenAndServe(":8080", mux)

	srv := &http.Server{Addr: ":8080", Handler: mux}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	return srv.ListenAndServe()
}

func main() {
	if err := initConfig(); err != nil {
		secrt.Exit(1, err)
	}

	// the wg is used to track running processes and ensure a clean shutdown.
	wg := &sync.WaitGroup{}

	mustInitPGX()
	mustInitPgpkg()

	if len(os.Args) == 3 && os.Args[1] == "add" {
		err := addServerCmd(os.Args[2])
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// start as many mail pollers as you like, to increase concurrency.
	startMailPoller(wg, 2)

	go StartReaper()

	_ = ListenAndServe()

	stopMailPoller()
	wg.Wait()
}
