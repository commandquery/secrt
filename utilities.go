package secrt

import (
	_ "embed"
	"fmt"
	"os"
)

//go:embed USAGE.md
var README string

// To32 converts a slice to a 32 byte array for use with nacl/box.
func To32(bytes []byte) *[32]byte {
	var result [32]byte
	if copy(result[:], bytes) != 32 {
		panic(fmt.Errorf("attempted to create non-32 byte key"))
	}

	return &result
}

// To64 converts a slice to a 64 byte array for use with nacl/sign.
func To64(bytes []byte) *[64]byte {
	var result [64]byte
	if copy(result[:], bytes) != 64 {
		panic(fmt.Errorf("attempted to create non-64 byte key"))
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
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}
