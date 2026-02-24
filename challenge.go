package secrt

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/sign"
)

const challengeLength = 1024

// NewChallenge generates a new, random challenge, encoded as a JSON object.
func NewChallenge(complexity int, signPrivateKey []byte) (*ChallengeRequest, error) {

	challenge := Challenge{
		Version:    1,
		Complexity: complexity,
		Timestamp:  time.Now().Unix(),
		Challenge:  make([]byte, challengeLength),
	}

	_, _ = rand.Read(challenge.Challenge)

	// Turn the challenge into a byte slice so we can sign it.
	challengejs, err := json.Marshal(challenge)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal challenge: %w", err)
	}

	return &ChallengeRequest{
		Challenge: sign.Sign(nil, challengejs, To64(signPrivateKey)),
	}, nil
}

// validateSolution checks if the given hash slice matches
// the given complexity (number of leading zero bits).
// We do this by reading the first 8 bytes of the hash as a uint64,
// and comparing them with a mask.
func validateSolution(complexity int, hash []byte) bool {

	// The maximum solution size is currently 64 bits, which fits into a uint64.
	solution := binary.BigEndian.Uint64(hash)

	// We only care about the most significant _complexity_ bits
	// So, mask out the less significant bits.
	// For complexity=5, this gives us 111110000000...
	mask := ^(uint64(18446744073709551615) >> complexity)

	// If the top bits of the solution are all zeroes then AND with the mask
	// will return zero.
	return (solution & mask) == 0
}

func ValidateResponse(response *ChallengeResponse, signPublicKey []byte) error {
	var out []byte
	challengeBytes, ok := sign.Open(out, response.Challenge, To32(signPublicKey))

	if !ok {
		return fmt.Errorf("invalid challenge signature")
	}

	var challenge Challenge
	if err := json.Unmarshal(challengeBytes, &challenge); err != nil {
		return fmt.Errorf("unable to unmarshal challenge: %w", err)
	}

	if len(challenge.Challenge) != challengeLength {
		return fmt.Errorf("invalid challenge length %d; expected %d", len(challenge.Challenge), challengeLength)
	}

	if challenge.Version != 1 {
		return fmt.Errorf("invalid challenge version %d", challenge.Version)
	}

	delta := time.Now().Unix() - challenge.Timestamp
	if delta < 0 || delta > 30 {
		return fmt.Errorf("challenge exprired")
	}

	hash := HashWithNonce(challenge.Challenge, response.Nonce)

	if validateSolution(challenge.Complexity, hash) {
		return nil
	}

	return fmt.Errorf("invalid challenge response")
}

func HashWithNonce(challenge []byte, nonce uint64) []byte {
	nonceSlice := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceSlice, nonce)

	hash := sha512.New()
	hash.Write(nonceSlice)
	hash.Write(challenge)
	return hash.Sum(nil)
}

// SolveChallenge solves a ChallengeRequest by creating a ChallengeResult
func SolveChallenge(request *ChallengeRequest) (*ChallengeResponse, error) {

	// Just get the challenge itself; only the server cares about the signature.
	challengeBytes := request.Challenge[sign.Overhead:]

	var challenge Challenge
	if err := json.Unmarshal(challengeBytes, &challenge); err != nil {
		return nil, fmt.Errorf("unable to unmarshal challenge: %w", err)
	}

	for nonce := uint64(0); nonce < 4294967295; nonce++ {

		sum := HashWithNonce(challenge.Challenge, nonce)

		if validateSolution(challenge.Complexity, sum) {
			return &ChallengeResponse{
				Challenge: request.Challenge,
				Nonce:     nonce,
			}, nil
		}
	}

	panic("No nonce found")
}
