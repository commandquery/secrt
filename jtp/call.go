package jtp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"
)

var client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	},
}

var debug = os.Getenv("SECRT_DEBUG_JSON") == "true"

// Request represents a HTTP call to a server, and contains the types being sent and received.
type Request[S any, R any] struct {
	Ctx     context.Context
	Method  string
	URL     string
	Headers http.Header
	Send    *S
	Recv    *R
}

// Call sends a JSON object and receives a JSON response. It's a convenience method that
// creates a Request and calls it. The intent is that most calls should use
// this method, but some requests are more complex and require additional settings
// (unsigned requests, headers, etc).
func Call[S any, R any](method string, uri string, headers http.Header, s *S, r *R) error {
	request := Request[S, R]{
		Ctx:     context.Background(),
		Method:  method,
		URL:     uri,
		Headers: headers,
		Send:    s,
		Recv:    r,
	}

	return DoRequest[S, R](&request)
}

func printJSON(v any) {
	if v == Nil {
		return
	}
	js, _ := json.MarshalIndent(v, "", "  ")
	_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", reflect.TypeOf(v), string(js))
}

func DoRequest[S any, R any](r *Request[S, R]) error {

	if debug {
		_, _ = fmt.Fprintf(os.Stderr, "\n%s %s\n", r.Method, r.URL)
		if r.Headers != nil {
			_, _ = fmt.Fprintln(os.Stderr, r.Headers)
		}
		printJSON(r.Send)
	}

	var reader io.Reader = http.NoBody

	if r.Send != nil {
		js, err := json.Marshal(r.Send)
		if err != nil {
			return fmt.Errorf("unable to marshal json: %v", err)
		}

		reader = bytes.NewReader(js)
	}

	req, err := http.NewRequestWithContext(r.Ctx, r.Method, r.URL, reader)
	if err != nil {
		return err
	}

	if reader != http.NoBody {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Accept", "application/json")

	if r.Headers != nil {
		for k, v := range r.Headers {
			for _, val := range v {
				req.Header.Add(k, val)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &HTTPError{StatusCode: resp.StatusCode}
	}

	if r.Recv == nil {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %w", err)
	}

	if err = json.Unmarshal(body, r.Recv); err != nil {
		return fmt.Errorf("unable to unmarshal response: %w", err)
	}

	if debug {
		printJSON(r.Recv)
	}

	return nil
}
