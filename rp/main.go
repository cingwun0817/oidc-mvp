package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"rp/internal/pkce"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

/*
最小職責：
- GET /         → 產 PKCE、導向 OP /authorize
- GET /callback → 用 code 換 token、驗 ID Token、建立 session（示範以 cookie 存 access_token）
- 依賴：OP 的記憶體內建 client_id=rp-web、redirect=http://localhost:9090/callback
*/

var (
	issuer      = env("OP_ISSUER", "http://localhost:8080") // 你的 OP URL
	clientID    = env("RP_CLIENT_ID", "rp-web")
	redirectURI = env("RP_REDIRECT_URI", "http://localhost:9090/callback")
	state       = fmt.Sprintf("st-%d", time.Now().UnixNano()) // demo：真實請改成每次隨機
	nonce       = fmt.Sprintf("n-%d", time.Now().UnixNano())  // demo：真實請改成每次隨機

	codeVerifier string // 暫存單次登入流程的 verifier（示範用）
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type jwks struct {
	Keys []jwk `json:"keys"`
}

func main() {
	app := fiber.New()

	// Step 1: 入口 → 導向 /authorize
	app.Get("/", func(c *fiber.Ctx) error {
		verifier, challenge := pkce.NewPair()
		codeVerifier = verifier

		q := url.Values{}
		q.Set("response_type", "code")
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("scope", "openid profile email")
		q.Set("state", state)
		q.Set("nonce", nonce)
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")

		return c.Redirect(issuer + "/authorize?" + q.Encode())
	})

	// Step 2: Callback → 用 code 換 token、驗 ID Token、建立 session
	app.Get("/callback", func(c *fiber.Ctx) error {
		if s := c.Query("state"); s == "" || s != state {
			return c.Status(400).SendString("state mismatch")
		}
		code := c.Query("code")
		if code == "" {
			return c.Status(400).SendString("missing code")
		}

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", redirectURI)
		form.Set("code_verifier", codeVerifier)
		form.Set("client_id", clientID) // public client（配合 OP 強制 PKCE）

		resp, err := http.Post(
			issuer+"/token",
			"application/x-www-form-urlencoded",
			bytes.NewBufferString(form.Encode()),
		)
		if err != nil {
			return c.Status(502).SendString("token exchange error: " + err.Error())
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return c.Status(resp.StatusCode).SendString(string(body))
		}

		var tr struct {
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			AccessToken string `json:"access_token"`
			IDToken     string `json:"id_token"`
		}
		if err := json.Unmarshal(body, &tr); err != nil {
			return c.Status(502).SendString("bad token response")
		}

		// 取 JWKS 並驗 ID Token（RS256 + kid）
		pubKey, kid, err := fetchRSAPublicKey(issuer)
		if err != nil {
			return c.Status(502).SendString("jwks fetch fail: " + err.Error())
		}
		claims, err := verifyIDToken(tr.IDToken, pubKey, kid, clientID, issuer)
		if err != nil {
			return c.Status(401).SendString("invalid id_token: " + err.Error())
		}

		// 登入完成 → 設定 session（示範：用 cookie 存 access token；正式請用 server-side session）
		c.Cookie(&fiber.Cookie{
			Name:     "sid",
			Value:    tr.AccessToken,
			HTTPOnly: true,
			SameSite: "Lax",
			// Secure: true, // 上線請開啟 HTTPS 再啟用
			MaxAge: tr.ExpiresIn,
		})

		return c.JSON(fiber.Map{
			"login":  "ok",
			"claims": claims,
			"token":  tr,
		})
	})

	log.Println("RP listening on :9090  → open http://localhost:9090/")
	log.Fatal(app.Listen(":9090"))
}

func fetchRSAPublicKey(iss string) (*rsa.PublicKey, string, error) {
	resp, err := http.Get(iss + "/.well-known/jwks.json")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, "", err
	}
	if len(set.Keys) == 0 {
		return nil, "", errors.New("empty jwks")
	}
	k := set.Keys[0]

	// 解析 N、E → rsa.PublicKey
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, "", fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, "", fmt.Errorf("decode e: %w", err)
	}
	var e int
	for _, b := range eBytes {
		e = e*256 + int(b) // big-endian bytes → int
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}
	return pub, k.Kid, nil
}

func verifyIDToken(raw string, pub *rsa.PublicKey, expectedKID, clientID, issuer string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	tok, err := parser.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != expectedKID {
			return nil, errors.New("kid mismatch")
		}
		return pub, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token invalid")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("claims type")
	}
	// 基本宣告驗證（建議都做）
	if claims["iss"] != issuer {
		return nil, errors.New("iss mismatch")
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != clientID {
			return nil, errors.New("aud mismatch")
		}
	case []any:
		found := false
		for _, v := range aud {
			if s, _ := v.(string); s == clientID {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("aud mismatch (array)")
		}
	default:
		return nil, errors.New("aud type")
	}
	// exp/iat 由 jwt/v5 已做基礎驗證；必要時再自訂嚴格度
	return claims, nil
}
