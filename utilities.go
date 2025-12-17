package secret

import (
	_ "embed"
	"fmt"
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
