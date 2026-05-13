package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/skip2/go-qrcode"
)

const (
	cookieName     = "qr_session"
	deviceTokenTTL = 5 * time.Minute
	sessionTTL     = 8 * time.Hour
)

type appConfig struct {
	ClientID                  string
	ClientSecret              string
	RedirectURI               string
	RedisAddr                 string
	AllowedEmail              string
	PublicURL                 string
	PostLoginURL              string
	CookieDomain              string
	OAuth2ProxyCookieSecret   string
}

type deviceToken struct {
	Status    string `json:"status"` // "pending" | "authed"
	SessionID string `json:"session_id,omitempty"`
	RD        string `json:"rd,omitempty"`
}

type sessionData struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

var (
	ac  appConfig
	rdb *redis.Client
)

func main() {
	ac = appConfig{
		ClientID:                mustEnv("GITLAB_CLIENT_ID"),
		ClientSecret:            mustEnv("GITLAB_CLIENT_SECRET"),
		RedirectURI:             mustEnv("GITLAB_REDIRECT_URI"),
		RedisAddr:               getEnv("REDIS_ADDR", "localhost:6379"),
		AllowedEmail:            mustEnv("ALLOWED_EMAIL"),
		PublicURL:               mustEnv("PUBLIC_URL"),
		PostLoginURL:            getEnv("POST_LOGIN_URL", "/"),
		CookieDomain:            getEnv("COOKIE_DOMAIN", ""),
		OAuth2ProxyCookieSecret: getEnv("OAUTH2_PROXY_COOKIE_SECRET", ""),
	}

	rdb = redis.NewClient(&redis.Options{Addr: ac.RedisAddr})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /auth", handleAuth)
	mux.HandleFunc("GET /device", handleDevice)
	mux.HandleFunc("GET /callback", handleCallback)
	mux.HandleFunc("GET /poll", handlePoll)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /_qr/", handleIndex)

	log.Println("listening :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// handleAuth is the Traefik ForwardAuth endpoint.
func handleAuth(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		redirectToQR(w, r)
		return
	}
	exists, err := rdb.Exists(r.Context(), "session:"+cookie.Value).Result()
	if err != nil || exists == 0 {
		http.SetCookie(w, expiredCookie())
		redirectToQR(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func redirectToQR(w http.ResponseWriter, r *http.Request) {
	rd := ac.PostLoginURL
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		uri := r.Header.Get("X-Forwarded-Uri")
		rd = "https://" + host + uri
	}
	http.Redirect(w, r, ac.PublicURL+"/_qr/?rd="+url.QueryEscape(rd), http.StatusFound)
}

// handleIndex serves the QR code page to the PC browser.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/_qr/" {
		http.NotFound(w, r)
		return
	}
	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = ac.PostLoginURL
	}

	token := randHex(16)
	dt := deviceToken{Status: "pending", RD: rd}
	data, _ := json.Marshal(dt)
	rdb.Set(r.Context(), "device:"+token, data, deviceTokenTTL)

	deviceURL := ac.PublicURL + "/device?token=" + token
	png, err := qrcode.Encode(deviceURL, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr generation failed", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	indexTmpl.Execute(w, map[string]any{
		"Token": token,
		"QR":    template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		"RD":    rd,
	})
}

// handleDevice is opened on the phone after scanning QR — starts GitLab OAuth.
func handleDevice(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", 400)
		return
	}
	val, err := rdb.Get(r.Context(), "device:"+token).Result()
	if err != nil {
		http.Error(w, "QR code expired — refresh the screen and try again", 400)
		return
	}
	var dt deviceToken
	json.Unmarshal([]byte(val), &dt)
	if dt.Status != "pending" {
		http.Error(w, "QR code already used", 400)
		return
	}

	authURL := "https://gitlab.com/oauth/authorize?" + url.Values{
		"client_id":     {ac.ClientID},
		"redirect_uri":  {ac.RedirectURI},
		"response_type": {"code"},
		"scope":         {"read_user openid"},
		"state":         {token},
	}.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback receives the GitLab OAuth callback on the phone's browser.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Error(w, "OAuth error: "+errParam, 400)
		return
	}
	if token == "" || code == "" {
		http.Error(w, "bad callback", 400)
		return
	}

	ctx := r.Context()
	val, err := rdb.Get(ctx, "device:"+token).Result()
	if err != nil {
		http.Error(w, "QR code expired", 400)
		return
	}
	var dt deviceToken
	json.Unmarshal([]byte(val), &dt)
	if dt.Status != "pending" {
		http.Error(w, "QR code already used", 400)
		return
	}

	email, username, err := exchangeCode(ctx, code)
	if err != nil {
		log.Printf("token exchange: %v", err)
		http.Error(w, "authentication failed", 500)
		return
	}
	if !strings.EqualFold(email, ac.AllowedEmail) {
		http.Error(w, "not authorized", 403)
		return
	}

	sessionID := randHex(32)
	sess := sessionData{Email: email, Username: username}
	sessData, _ := json.Marshal(sess)
	rdb.Set(ctx, "session:"+sessionID, sessData, sessionTTL)

	dt.Status = "authed"
	dt.SessionID = sessionID
	updated, _ := json.Marshal(dt)
	rdb.Set(ctx, "device:"+token, updated, deviceTokenTTL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	phoneTmpl.Execute(w, map[string]string{
		"Email":     email,
		"Username":  username,
		"SessionID": sessionID,
	})
}

// handlePoll is polled by the PC browser waiting for phone auth.
func handlePoll(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", 400)
		return
	}
	ctx := r.Context()
	val, err := rdb.Get(ctx, "device:"+token).Result()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "expired"})
		return
	}
	var dt deviceToken
	json.Unmarshal([]byte(val), &dt)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if dt.Status == "authed" {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    dt.SessionID,
			MaxAge:   int(sessionTTL.Seconds()),
			Domain:   ac.CookieDomain,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		if ac.OAuth2ProxyCookieSecret != "" {
			var sd sessionData
			if raw, err := rdb.Get(ctx, "session:"+dt.SessionID).Result(); err == nil {
				json.Unmarshal([]byte(raw), &sd)
			}
			if sd.Email != "" {
				if val, err := forgeOAuth2ProxyCookie(sd.Email, sd.Username, ac.OAuth2ProxyCookieSecret); err == nil {
					http.SetCookie(w, &http.Cookie{
						Name:     "_oauth2_proxy",
						Value:    val,
						MaxAge:   int(sessionTTL.Seconds()),
						Domain:   ac.CookieDomain,
						Path:     "/",
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
					})
				} else {
					log.Printf("forgeOAuth2ProxyCookie: %v", err)
				}
			}
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":   "authed",
			"redirect": dt.RD,
		})
		rdb.Del(ctx, "device:"+token)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
}

// handleLogout is called from the phone to end the session.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.FormValue("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id", 400)
		return
	}
	rdb.Del(r.Context(), "session:"+sessionID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	logoutTmpl.Execute(w, nil)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func exchangeCode(ctx context.Context, code string) (email, username string, err error) {
	resp, err := http.PostForm("https://gitlab.com/oauth/token", url.Values{
		"client_id":     {ac.ClientID},
		"client_secret": {ac.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {ac.RedirectURI},
	})
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return
	}
	if tokenResp.Error != "" {
		err = fmt.Errorf("gitlab: %s", tokenResp.Error)
		return
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://gitlab.com/api/v4/user", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer userResp.Body.Close()
	userBody, _ := io.ReadAll(userResp.Body)

	var user struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}
	if err = json.Unmarshal(userBody, &user); err != nil {
		return
	}
	email, username = user.Email, user.Username
	return
}

// forgeOAuth2ProxyCookie creates a cookie value accepted by oauth2-proxy (chart 10.x / app v7.x).
// It replicates oauth2-proxy's AES-256-GCM cookie cipher exactly:
//   - base64-decode the secret (matches oauth2-proxy's SecretBytes helper)
//   - SHA-256 hash → 32-byte AES key
//   - AES-GCM encrypt the JSON session; prepend nonce; base64-RawURL encode
func forgeOAuth2ProxyCookie(email, user, encodedSecret string) (string, error) {
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		if secret, err = base64.URLEncoding.DecodeString(encodedSecret); err != nil {
			secret = []byte(encodedSecret)
		}
	}

	h := sha256.Sum256(secret)
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	now := time.Now()
	expires := now.Add(sessionTTL)
	type oauthSession struct {
		CreatedAt *time.Time `json:"ca"`
		ExpiresOn *time.Time `json:"ea"`
		Email     string     `json:"e"`
		User      string     `json:"u"`
	}
	plaintext, err := json.Marshal(oauthSession{CreatedAt: &now, ExpiresOn: &expires, Email: email, User: user})
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil)), nil
}

func expiredCookie() *http.Cookie {
	return &http.Cookie{
		Name: cookieName, Value: "", MaxAge: -1,
		Domain: ac.CookieDomain, Path: "/", HttpOnly: true, Secure: true,
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s not set", key)
	}
	return v
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ── Templates ────────────────────────────────────────────────────────────────

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hippotion Homelab</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#c9d1d9}
.card{text-align:center;padding:2.5rem 2rem;background:#161b22;
      border:1px solid #30363d;border-radius:16px;width:90%;max-width:360px}
.brand{font-size:.9rem;font-weight:600;color:#58a6ff;letter-spacing:.08em;
       text-transform:uppercase;margin-bottom:1.8rem}
.qr{display:inline-block;padding:1rem;background:#fff;border-radius:10px;margin-bottom:1.5rem}
.qr img{display:block;width:200px;height:200px}
h2{font-size:1rem;font-weight:500;color:#e6edf3;margin-bottom:.4rem}
p{font-size:.8rem;color:#8b949e;margin-bottom:1.8rem}
.status{display:flex;align-items:center;justify-content:center;gap:.5rem;font-size:.82rem;color:#8b949e}
.dot{width:8px;height:8px;border-radius:50%;background:#58a6ff;
     animation:pulse 1.4s ease-in-out infinite;flex-shrink:0}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.ok .dot{background:#3fb950;animation:none}
.ok{color:#3fb950}
.err .dot{background:#f85149;animation:none}
.err{color:#f85149}
.expires{font-size:.72rem;color:#484f58;margin-top:1rem}
</style>
</head>
<body data-token="{{.Token}}" data-rd="{{.RD}}">
<div class="card">
  <div class="brand">homelab</div>
  <div class="qr"><img src="{{.QR}}" alt="Login QR Code"></div>
  <h2>Scan to log in</h2>
  <p>Point your phone's camera at the code,<br>then approve on GitLab.</p>
  <div class="status" id="st">
    <div class="dot"></div>
    <span id="msg">Waiting for phone…</span>
  </div>
  <div class="expires">QR expires in <span id="cd">5:00</span></div>
</div>
<script>
(function(){
  var token = document.body.dataset.token;
  var rd    = document.body.dataset.rd;
  var secs  = 300;
  var cdEl  = document.getElementById('cd');
  var stEl  = document.getElementById('st');
  var msgEl = document.getElementById('msg');

  var timer = setInterval(function(){
    secs--;
    if(secs <= 0){
      clearInterval(timer);
      stEl.className = 'status err';
      msgEl.textContent = 'QR expired — refresh to get a new one.';
      return;
    }
    var m = Math.floor(secs/60), s = secs%60;
    cdEl.textContent = m + ':' + (s < 10 ? '0' : '') + s;
  }, 1000);

  var attempt = 0;
  function poll(){
    if(secs <= 0) return;
    fetch('/poll?token=' + token, {credentials: 'same-origin'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(d.status === 'authed'){
          clearInterval(timer);
          stEl.className = 'status ok';
          msgEl.textContent = 'Authenticated! Redirecting…';
          setTimeout(function(){ window.location = d.redirect || rd; }, 700);
          return;
        }
        if(d.status === 'expired'){
          clearInterval(timer);
          stEl.className = 'status err';
          msgEl.textContent = 'QR expired — refresh to get a new one.';
          return;
        }
        attempt++;
        setTimeout(poll, attempt < 90 ? 2000 : 5000);
      })
      .catch(function(){
        attempt++;
        setTimeout(poll, 3000);
      });
  }
  poll();
})();
</script>
</body>
</html>
`))

var phoneTmpl = template.Must(template.New("phone").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Session Active</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#c9d1d9}
.card{text-align:center;padding:2rem 1.5rem;background:#161b22;
      border:1px solid #30363d;border-radius:16px;width:90%;max-width:340px}
.icon{font-size:2.8rem;color:#3fb950;margin-bottom:1rem}
h1{font-size:1.1rem;font-weight:600;color:#e6edf3;margin-bottom:.3rem}
.sub{font-size:.8rem;color:#8b949e;margin-bottom:.2rem}
.email{font-size:.88rem;color:#58a6ff;margin-bottom:2rem}
.btn{background:#da3633;color:#fff;border:none;border-radius:8px;
     padding:.8rem;font-size:.95rem;font-weight:500;cursor:pointer;width:100%}
.btn:active{opacity:.75}
.btn:disabled{opacity:.4;cursor:default}
.done{color:#3fb950;margin-top:1rem;font-size:.85rem;display:none}
</style>
</head>
<body data-sid="{{.SessionID}}">
<div class="card">
  <div class="icon">✓</div>
  <h1>Screen unlocked</h1>
  <div class="sub">Logged in as</div>
  <div class="email">{{.Email}}</div>
  <button class="btn" id="btn" onclick="endSession()">End Session</button>
  <div class="done" id="done">Session ended. The screen is locked.</div>
</div>
<script>
function endSession(){
  var btn = document.getElementById('btn');
  btn.disabled = true;
  var form = new FormData();
  form.append('session_id', document.body.dataset.sid);
  fetch('/logout', {method:'POST', body:form, credentials:'same-origin'})
    .then(function(){ document.getElementById('done').style.display = 'block'; })
    .catch(function(){ btn.disabled = false; });
}
</script>
</body>
</html>
`))

var logoutTmpl = template.Must(template.New("logout").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Logged Out</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#c9d1d9}
.card{text-align:center;padding:2rem;background:#161b22;
      border:1px solid #30363d;border-radius:16px;max-width:300px;width:90%}
.icon{font-size:2.5rem;margin-bottom:1rem}
h2{font-size:1rem;color:#e6edf3;margin-bottom:.5rem}
p{font-size:.82rem;color:#8b949e}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🔒</div>
  <h2>Session ended</h2>
  <p>The screen is now locked.</p>
</div>
</body>
</html>
`))
