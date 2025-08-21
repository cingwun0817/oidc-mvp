package util

import (
	"crypto/sha256"
	"encoding/base64"
)

func VerifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return want == challenge
}
