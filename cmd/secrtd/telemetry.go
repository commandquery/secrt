package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

func (server *SecretServer) handlePostTelemetry(r *http.Request, telemetry *secrt.Telemetry) (*jtp.None, error) {
	js, err := json.Marshal(telemetry)
	if err != nil {
		return nil, jtp.BadRequestError(err)
	}

	ctx := context.Background()
	_, err = PGXPool.Exec(ctx, "select secrt.post_telemetry($1, $2::jsonb)", r.RemoteAddr, js)
	if err != nil {
		// Don't return an error to the client, it doesn't help them.
		log.Println("unable to post telemetry:", err)
	}

	return jtp.Nil, nil
}
