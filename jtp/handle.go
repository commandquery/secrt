package jtp

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type JSFunc[IN any, OUT any] func(http.ResponseWriter, *http.Request, *IN) (*OUT, error)

func LogError(w http.ResponseWriter, status int, err error) {
	if err != nil {
		log.Printf("%v (http %d)", err, status)
	} else if status >= 400 {
		log.Printf("http %d", status)
	}
	http.Error(w, http.StatusText(status), status)
}

// Handle returns a http.ServeFunc that automatically marshals and unmarshals the parameter and return type.
//
// If the IN type is declared as the value None, nothing is read from the request body.
// If the OUT type is declared as the value None, or the return value is nil, nothing is written in the response.
//
// The function can return an error. nil returns http.StatusOK to the client. If the error contains a value
// of type HTTPError, the associated status is returned. Otherwise, we return InternalServerError.
// Errors are logged using standard logging.
func Handle[IN any, OUT any](handler JSFunc[IN, OUT]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// If the request type (IN) is not the type None, read the body.
		var in IN
		if _, ok := any(in).(None); !ok {
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				LogError(w, http.StatusBadRequest, err)
				return
			}
		}

		out, err := handler(w, r, &in)

		if err != nil {
			var httpErr *HTTPError
			ok := errors.As(err, &httpErr)
			if ok {
				LogError(w, httpErr.StatusCode, httpErr.Err)
				return
			} else {
				LogError(w, http.StatusInternalServerError, err)
				return
			}
		}

		if out != nil {
			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(out)
			if err != nil {
				// It's probably too late to do anything at this point.
				LogError(w, http.StatusBadRequest, err)
			}
		}
	}
}
