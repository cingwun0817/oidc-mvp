package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"op/internal/crypto"
	"op/internal/storage"
	"op/internal/util"
)

var (
	issuer  = env("OP_ISSUER", "http://localhost:8080")
	kid     = env("OP_KID", "kid-1")
	keyPath = env("OP_PRIVATE_KEY_PATH", "../scripts/op_rsa.pem")
	privKey *rsa.PrivateKey
	mem     = storage.NewMemory()
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var err error
	privKey, err = crypto.LoadPrivateKey(keyPath)
	if err != nil {
		log.Fatalf("load key: %v", err)
	}

	app := fiber.New()

	// -----------------------
	// Discovery
	// -----------------------
	app.Get("/.well-known/openid-configuration", func(c *fiber.Ctx) error {
		conf := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"jwks_uri":                              issuer + "/.well-known/jwks.json",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		return c.JSON(conf)
	})

	// -----------------------
	// JWKS
	// -----------------------
	app.Get("/.well-known/jwks.json", func(c *fiber.Ctx) error {
		j := crypto.PublicJWKS(kid, privKey)
		return c.JSON(j)
	})

	// -----------------------
	// Login Page (簡單版)
	// -----------------------
	app.Get("/login", func(c *fiber.Ctx) error {
		ret := c.Query("return_to")
		html := `
<!doctype html><html><body>
<h3>Login (demo/demo)</h3>
<form method="POST" action="/login">
  <input type="hidden" name="return_to" value="` + ret + `">
  <label>Username:<input name="username" value="demo"></label><br>
  <label>Password:<input name="password" value="demo" type="password"></label><br>
  <button type="submit">Login</button>
</form>
</body></html>`
		return c.Type("html").SendString(html)
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		u := c.FormValue("username")
		p := c.FormValue("password")
		ret := c.FormValue("return_to")
		user, err := mem.CheckUserPassword(u, p)
		if err != nil {
			return c.Status(401).SendString("invalid credentials")
		}
		// 在 cookie 記錄 user id
		c.Cookie(&fiber.Cookie{
			Name:     "uid",
			Value:    user.ID,
			HTTPOnly: true,
			SameSite: "Lax",
		})
		return c.Redirect(ret)
	})

	// -----------------------
	// Authorization Endpoint
	// -----------------------
	app.Get("/authorize", func(c *fiber.Ctx) error {
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		respType := c.Query("response_type") // code
		state := c.Query("state")
		nonce := c.Query("nonce")
		cc := c.Query("code_challenge")
		ccm := c.Query("code_challenge_method")

		cl, ok := mem.GetClient(clientID)
		if !ok || respType != "code" {
			return c.Status(400).SendString("bad request")
		}
		// 驗 redirect
		okRedirect := false
		for _, ru := range cl.RedirectURIs {
			if ru == redirectURI {
				okRedirect = true
				break
			}
		}
		if !okRedirect {
			return c.Status(400).SendString("redirect_uri mismatch")
		}

		// 確認是否登入
		uid := c.Cookies("uid")
		if uid == "" {
			returnTo := issuer + "/authorize?" + c.Context().QueryArgs().String()
			return c.Redirect("/login?return_to=" + url.QueryEscape(returnTo))
		}

		// 發 Code
		code, _, _ := mem.NewAuthCode(clientID, uid, redirectURI, "openid", nonce, cc, ccm, 5*time.Minute)
		q := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, url.QueryEscape(code), url.QueryEscape(state))
		return c.Redirect(q)
	})

	// -----------------------
	// Token Endpoint
	// -----------------------
	app.Post("/token", func(c *fiber.Ctx) error {
		grantType := c.FormValue("grant_type")
		if grantType != "authorization_code" {
			return c.Status(400).JSON(fiber.Map{"error": "unsupported_grant_type"})
		}
		code := c.FormValue("code")
		redirectURI := c.FormValue("redirect_uri")
		codeVerifier := c.FormValue("code_verifier")
		clientID := c.FormValue("client_id")

		sum := sha256.Sum256([]byte(code))
		hash := base64.RawURLEncoding.EncodeToString(sum[:])
		ac, err := mem.ConsumeAuthCode(hash)
		if err != nil || ac.ClientID != clientID || ac.RedirectURI != redirectURI {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_grant"})
		}
		// 驗 PKCE
		if !util.VerifyPKCE(ac.CodeChallenge, ac.Method, codeVerifier) {
			return c.Status(400).JSON(fiber.Map{"error": "pkce_failed"})
		}

		// 發 access token 與 id_token
		accessRaw, _ := mem.NewToken("access", clientID, ac.UserID, "openid", 15*time.Minute)
		idToken, _ := signIDToken(ac.UserID, clientID, ac.Nonce)

		return c.JSON(fiber.Map{
			"token_type":   "Bearer",
			"expires_in":   900,
			"access_token": accessRaw,
			"id_token":     idToken,
		})
	})

	// -----------------------
	// UserInfo
	// -----------------------
	app.Get("/userinfo", func(c *fiber.Ctx) error {
		auth := c.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return c.Status(401).SendString("missing bearer")
		}
		raw := strings.TrimPrefix(auth, "Bearer ")
		sum := sha256.Sum256([]byte(raw))
		hash := base64.RawURLEncoding.EncodeToString(sum[:])
		tok, ok := mem.GetActiveToken(hash, "access")
		if !ok {
			return c.Status(401).SendString("invalid token")
		}
		return c.JSON(fiber.Map{
			"sub":   tok.UserID,
			"email": "demo@example.com",
			"name":  "Demo User",
		})
	})

	log.Printf("OP listening on :8080 issuer=%s", issuer)
	log.Fatal(app.Listen(":8080"))
}

func signIDToken(sub, aud, nonce string) (string, error) {
	now := time.Now()
	cl := jwt.MapClaims{
		"iss":   issuer,
		"sub":   sub,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
		"nonce": nonce,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, cl)
	t.Header["kid"] = kid
	return t.SignedString(privKey)
}
