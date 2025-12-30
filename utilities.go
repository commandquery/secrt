package secrt

import (
	_ "embed"
	"fmt"
	"os"
)

//go:embed README.md
var README string

// To32 converts a slice to a 32 byte array for use with nacl.
func To32(bytes []byte) *[32]byte {
	var result [32]byte
	if copy(result[:], bytes) != 32 {
		panic(fmt.Errorf("Attempted to create non-32 bit key"))
	}

	return &result
}

func Usage(msg ...any) {

	_, _ = os.Stderr.WriteString(README)
	fmt.Println()

	if len(msg) > 0 {
		fmt.Println()
		fmt.Println(msg...)
		fmt.Println()
	}

	os.Exit(1)
}

func Exit(code int, err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(code)
}
