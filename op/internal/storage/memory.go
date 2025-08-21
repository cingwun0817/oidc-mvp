package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

type User struct {
	ID       string
	Username string
	PassHash string // 這裡示範用明文 "demo" 的 sha256，實務請改 Argon2id
	Email    string
}

type Client struct {
	ClientID      string
	RedirectURIs  []string
	Scopes        []string
	PKCEMandatory bool
}

type AuthCode struct {
	Hash          string
	ClientID      string
	UserID        string
	RedirectURI   string
	Scope         string
	Nonce         string
	CodeChallenge string
	Method        string
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

type Token struct {
	Hash      string
	Type      string // "access" or "refresh"
	ClientID  string
	UserID    string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

type Memory struct {
	mu        sync.Mutex
	Users     map[string]User     // by username
	Clients   map[string]Client   // by client_id
	AuthCodes map[string]AuthCode // by code_hash
	Tokens    map[string]Token    // by token_hash
}

func NewMemory() *Memory {
	return &Memory{
		Users: map[string]User{
			"demo": {ID: "u1", Username: "demo",
				PassHash: sha256Hex("demo"), Email: "demo@example.com"},
		},
		Clients: map[string]Client{
			"rp-web": {ClientID: "rp-web",
				RedirectURIs:  []string{"http://localhost:9090/callback"},
				Scopes:        []string{"openid", "profile", "email"},
				PKCEMandatory: true,
			},
		},
		AuthCodes: map[string]AuthCode{},
		Tokens:    map[string]Token{},
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (m *Memory) CheckUserPassword(username, pass string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[username]
	if !ok || u.PassHash != sha256Hex(pass) {
		return User{}, errors.New("invalid credentials")
	}
	return u, nil
}

func (m *Memory) GetClient(id string) (Client, bool) { c, ok := m.Clients[id]; return c, ok }

func rndURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *Memory) NewAuthCode(clientID, userID, redirectURI, scope, nonce, cc, method string, ttl time.Duration) (code, hash string, err error) {
	code = rndURL(32)
	hash = sha256Hex(code)
	m.mu.Lock()
	m.AuthCodes[hash] = AuthCode{
		Hash: hash, ClientID: clientID, UserID: userID,
		RedirectURI: redirectURI, Scope: scope, Nonce: nonce,
		CodeChallenge: cc, Method: method,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.mu.Unlock()
	return
}

func (m *Memory) ConsumeAuthCode(hash string) (AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ac, ok := m.AuthCodes[hash]
	if !ok || time.Now().After(ac.ExpiresAt) || ac.UsedAt != nil {
		return AuthCode{}, errors.New("invalid code")
	}
	now := time.Now()
	ac.UsedAt = &now
	m.AuthCodes[hash] = ac
	return ac, nil
}

func (m *Memory) NewToken(tokenType, clientID, userID, scope string, ttl time.Duration) (raw, hash string) {
	raw = rndURL(32)
	hash = sha256Hex(raw)
	m.mu.Lock()
	m.Tokens[hash] = Token{
		Hash: hash, Type: tokenType, ClientID: clientID, UserID: userID,
		Scope: scope, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(ttl),
	}
	m.mu.Unlock()
	return
}

func (m *Memory) GetActiveToken(hash, tokenType string) (Token, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[hash]
	if !ok || t.Type != tokenType || t.RevokedAt != nil || time.Now().After(t.ExpiresAt) {
		return Token{}, false
	}
	return t, true
}
