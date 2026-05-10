# jtp - JSON over HTTP

JTP is a simple library for making HTTP calls to JSON endpoints. It's super simple to use.

## Client

To call a JSON function from the client:

    var send struct {
        // json fields
    }

    var recv struct {
        // json fields
    }

    err := jtp.Call(method, uri, headers, send, &recv)
    if err ...

## Server

To handle a JSON call on the server:

    type R struct {
        // whatever you like.
    }

    // handleWhatever is generic - use whatever input and output struct you like.
    func handleSomething(w http.ResponseWriter, r *http.Request, in *SomeInputStruct) (*SomeOutputStruct, error) {
    }

Use jtp.None if you don't need recieve or send a value:

    func handleSomething(w http.ResponseWriter, r *http.Request, in *jtp.None) (*SomeOutputStruct, error)
    func handleSomething(w http.ResponseWriter, r *http.Request, in *SomeInputStruct) (*jtp.None, error)
    func handleSomething(w http.ResponseWriter, r *http.Request, in *jtp.None) (*jtp.None, error)

If there is an input struct, it is already unmarshalled for you, and the output struct is automatically marshalled. 

Pass the function to jtp.Handle to turn it into a http.ServeFunc:

    mux.HandleFunc("POST /whatever", jtp.Handle(handleWhatever)) 

return jtp.Nil if you don't need to return a JSON value.

## Errors

The error returned by jtp may be HTTP error, you can test for specific errors with errors.Is,
using the errors in error.go:

 	ErrBadRequest          = BadRequestError(nil)
	ErrNotFound            = NotFoundError(nil)
	ErrInternalServerError = InternalServerError(nil)
	ErrForbidden           = ForbiddenError(nil)
	ErrUnauthorized        = UnauthorizedError(nil)
	ErrConflict            = ConflictError(nil)
	ErrNoContent           = NoContentError()

for example, `errors.Is(err, ErrNotFound)` will return true if the call returns a 404.
You can check for arbitrary status with:

    errors.Is(err, &jtp.HTTPError{StatusCode: http.StatusTooManyRequests})

of course, JTP may return a non-http error which you can treat as normal.