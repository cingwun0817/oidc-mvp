package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("no pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err == nil {
		return key, nil
	}
	// PKCS8?
	priv, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not rsa")
	}
	return rk, nil
}

func PublicJWKS(kid string, pk *rsa.PrivateKey) JWKS {
	pub := &pk.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return JWKS{Keys: []JWK{{
		Kty: "RSA", Alg: "RS256", Use: "sig", Kid: kid, N: n, E: e,
	}}}
}

func MustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
