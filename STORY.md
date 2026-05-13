# Building a QR Code Login for a Homelab (And Accidentally Reverse-Engineering oauth2-proxy's Internals)

## The problem

My homelab runs a single-node k3s cluster with a full GitOps stack — Argo CD, Traefik, oauth2-proxy for GitLab SSO, the usual over-engineered personal project. One thing that always bothered me: when I want to show the Homer dashboard on the living room TV, I have to type my credentials on a keyboard that wasn't designed for the living room.

The obvious fix is a QR code. Phone scans it, phone authenticates, TV unlocks. Conceptually simple. In practice, a two-day debugging adventure that took me deep into oauth2-proxy's source code.

---

## The design

The flow I wanted:

1. TV opens `qr.hippotion.com`, shows a QR code and polls for completion
2. Phone scans, opens the device URL, taps "Continue with GitLab"
3. Phone completes GitLab OAuth
4. Server marks the session as ready
5. TV's poll fires, gets redirected to Homer
6. Later: phone taps "End Session", TV locks immediately

This is the [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) pattern adapted for a single trusted user. I wrote it in Go with Redis for session storage. The service generates a device token, stores it with a 5-minute TTL, and uses it as the OAuth `state` parameter. The phone completes GitLab OAuth and the callback handler links the resulting session to the device token. The TV's poll loop picks it up and redirects.

That part was straightforward. The hard part was making the TV's session work for *all* protected apps on the domain, not just the QR page.

---

## The oauth2-proxy problem

My homelab uses oauth2-proxy as a ForwardAuth backend for Traefik. Every protected app (`home.hippotion.com`, `argo.hippotion.com`, `grafana.hippotion.com`, etc.) sends unauthenticated requests through oauth2-proxy, which redirects to GitLab if no valid `_oauth2_proxy` session cookie is present.

The QR auth service creates its own session cookie (`qr_session`), but oauth2-proxy knows nothing about it. After QR login, clicking any link from Homer would immediately ask for GitLab credentials again.

The obvious solution: after the phone authenticates, set a valid `_oauth2_proxy` cookie on the TV's browser. If I can forge a cookie that oauth2-proxy accepts, all apps work instantly.

How hard can it be?

---

## Attempt 1: AES-GCM + JSON

I looked at the oauth2-proxy source and found what looked like the session format: a JSON struct with short field names (`"e"` for email, `"ca"` for created-at, etc.), encrypted with AES-GCM, base64url-encoded.

```go
type oauthSession struct {
    CreatedAt *time.Time `json:"ca"`
    ExpiresOn *time.Time `json:"ea"`
    Email     string     `json:"e"`
    User      string     `json:"u"`
}
```

SHA256-hash the cookie secret → 32-byte AES key → GCM encrypt → base64url encode. Set as `_oauth2_proxy` cookie. Clean, simple, wrong.

oauth2-proxy returned 302 every time. I added debug logging to print the cookie value, copied it, and tested it directly against the ForwardAuth endpoint with curl. The logs revealed everything:

```
Error loading cookied session: cookie signature not valid, removing session
```

*Cookie signature not valid.* Not "decryption failed", not "session expired". A signature check.

---

## Finding the real format

The error came from `pkg/middleware/stored_session.go:94`. I fetched the source:

```go
val, _, ok := encryption.Validate(c, secret, s.Cookie.Expire)
if !ok {
    return nil, errors.New("cookie signature not valid")
}
```

`encryption.Validate` splits the cookie value on `|` and expects three parts. Looking at `utils.go`:

```go
func Validate(cookie *http.Cookie, seed string, expiration time.Duration) (value []byte, t time.Time, ok bool) {
    parts := strings.Split(cookie.Value, "|")
    if len(parts) != 3 {
        return
    }
    if checkSignature(parts[2], seed, cookie.Name, parts[0], parts[1]) {
        // ...
    }
}
```

The cookie format is `encryptedValue|timestamp|hmac`. My cookie was just `encryptedValue`. Three-part, not one. First problem found.

For the HMAC, I needed to verify against a real cookie to get the key format right. oauth2-proxy sets `_oauth2_proxy_csrf` cookies during the login flow — I captured one from a 302 response and reverse-engineered it in Python:

```python
key = secret_raw.encode()  # raw string, not decoded
data = (cookie_name + enc_val + ts).encode()  # concatenated, NO separators
sig = base64.urlsafe_b64encode(hmac.new(key, data, hashlib.sha256).digest())
```

Two surprises: the HMAC key is the **raw cookie secret string** (not base64-decoded), and the input is a **bare concatenation** with no `|` separators between fields.

I ran the test. The CSRF cookie's signature matched. I had the format.

But oauth2-proxy still rejected the session.

---

## The wrong cipher

I switched from AES-GCM to the correct HMAC format and tried again. Still 302. `cookie signature not valid` again.

Wait — was it even getting to the signature check? If decryption failed first, it wouldn't reach that error. I added more debug logging to print the full cookie value and tested it with Python's `cryptography` library:

```python
candidates = {
    '24-byte std-b64 decode':  base64.b64decode(secret_str),
    '32-byte raw string':      secret_str.encode(),
    '32-byte sha256 of b64':   hashlib.sha256(base64.b64decode(secret_str)).digest(),
    ...
}
for label, key in candidates.items():
    try:
        pt = AESGCM(key).decrypt(nonce, ct_tag, None)
        print(f'SUCCESS [{label}]: {pt.decode()}')
    except Exception as e:
        print(f'FAIL    [{label}]: {e}')
```

The 24-byte base64-decoded key decrypted successfully. The cookie was correctly decrypted. But still rejected. Which meant the signature check was passing but *something else* was wrong upstream — it wasn't even getting to the signature.

I went back to the source. `session_store.go` → `NewCookieSessionStore`:

```go
cipher, err := encryption.NewCFBCipher(encryption.SecretBytes(secret))
```

**AES-CFB. Not GCM.** The cookie session store uses CFB. GCM exists in the codebase for a different purpose (the Redis ticket store, which I hadn't discovered yet). I had been encrypting with the wrong cipher the entire time.

And `SecretBytes` — a function I'd been reading but not understanding:

```go
func SecretBytes(secret string) []byte {
    b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(secret, "="))
    if err == nil {
        for _, i := range []int{16, 24, 32} {
            if len(b) == i {
                return b
            }
        }
    }
    return []byte(secret)  // fallback: raw string
}
```

The cookie secret `q7OF9sK2/Pnt9QKNoBBmxWRL3GAbWzvj` contains `/`. That's valid standard base64 but not URL-safe base64 — `RawURLEncoding` fails. Fallback to raw string: 32 bytes, valid AES-256 key. My Python test had used standard base64 decoding, which *did* succeed (and produced a different 24-byte key). My Go implementation had done the same. Both were deriving the wrong key.

I rewrote the cipher to AES-CFB with the raw-string key. New test. Same error. Still rejecting.

---

## MessagePack and LZ4

Back to the source. `EncodeSessionState`:

```go
func (s *SessionState) EncodeSessionState(c encryption.Cipher, compress bool) ([]byte, error) {
    packed, err := msgpack.Marshal(s)
    // ...
    compressed, err := lz4Compress(packed)
    // ...
    return c.Encrypt(compressed)
}
```

**MessagePack. LZ4 compression. Then AES-CFB.**

I had been encrypting raw JSON. The whole time.

The struct tags confirmed it:

```go
type SessionState struct {
    CreatedAt *time.Time `msgpack:"ca,omitempty"`
    ExpiresOn *time.Time `msgpack:"eo,omitempty"`  // "eo", not "ea" as I'd assumed
    AccessToken string   `msgpack:"at,omitempty"`
    Email      string    `msgpack:"e,omitempty"`
    User       string    `msgpack:"u,omitempty"`
}
```

Even the ExpiresOn field name was different from what I'd guessed (`"eo"` not `"ea"`).

I added the `vmihailenco/msgpack` and `pierrec/lz4` dependencies, rewrote the encoding pipeline: msgpack → lz4 → AES-CFB(raw-string key) → base64url(encrypted) → sign with HMAC.

Ran the curl test. **HTTP 200.**

After three days and four complete rewrites of the encoding logic, oauth2-proxy accepted the forged session.

---

## The access token problem

Celebrating was premature. The browser test worked from curl, but real ForwardAuth requests kept failing intermittently. Looking at the logs:

```
Error loading cookied session: session is invalid
```

This came from `validateSession` in the storedSessionLoader — after successfully loading the session, it was calling the provider's `ValidateSession` method and getting false back. I checked the GitLab provider:

```go
func (p *GitLabProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
    return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.IDToken))
}
```

oauth2-proxy calls GitLab's `/oauth/token/info` endpoint with the access token to verify the session is still active. My forged session had an empty `AccessToken` field. Empty access token → `validateToken` returns false immediately → session rejected.

The fix: during the phone's GitLab OAuth flow, `exchangeCode` was already calling GitLab's token endpoint and receiving an access token, but I'd been discarding it. I changed the function signature to return it, stored it in the session, included it in the forged session's `at` field.

The token was issued for my qr-auth GitLab app, not oauth2-proxy's app. But GitLab's `/oauth/token/info` endpoint doesn't check the issuing application — it just validates the token is active and returns 200. oauth2-proxy only checks for a 200 response. The token worked.

Everything worked.

---

## The End Session problem — three attempts

### Attempt 1: Delete qr_session, lock the QR page

The first End Session implementation deleted the `qr_session` key from Redis. To make this actually lock the screen, I restored the Homer proxy at `qr.hippotion.com` — the TV would show Homer via an ExternalName Kubernetes service pointing at the Homer pod, guarded by a Traefik ForwardAuth middleware that checked the `qr_session` cookie. Homer makes status API calls every ~30 seconds, which re-triggered ForwardAuth, and deleting `qr_session` meant the screen would lock within 30 seconds automatically.

This worked for `qr.hippotion.com`, but the `_oauth2_proxy` cookie was stateless — a signed, self-contained encrypted blob in the browser. There was no server-side record to delete. Other apps (`argo.hippotion.com`, `grafana.hippotion.com`, etc.) kept working until the 8-hour cookie expiry.

The TV screen was locked. The session wasn't.

### Attempt 2: Shorter cookie TTL

The tempting quick fix: reduce the forged cookie's TTL from 8 hours to something shorter, like 30 minutes. End Session would lock the TV immediately. Other apps would expire within 30 minutes on their own.

Rejected. 30 minutes of residual access on a shared TV is too long, and the TTL is arbitrary — it doesn't match what End Session is supposed to mean.

### Attempt 3: Redis-backed oauth2-proxy sessions

The correct fix is what oauth2-proxy calls *persistence tickets*. Instead of encoding the entire session into the cookie, oauth2-proxy stores the session in Redis and puts only a ticket reference in the cookie. When the ticket is deleted from Redis, the session is gone on the next request.

The ticket format, from `pkg/sessions/persistence/ticket.go`:

```go
// ticketID format: "_oauth2_proxy-<hex(16 random bytes)>"
ticketID := fmt.Sprintf("%s-%s", cookieOpts.Name, hex.EncodeToString(rawID))

// ticket string in the cookie: "v2.<base64url(ticketID)>.<base64url(ticketSecret)>"
func (t *ticket) encodeTicket() string {
    return fmt.Sprintf("v2.%s.%s",
        base64.RawURLEncoding.EncodeToString([]byte(t.id)),
        base64.RawURLEncoding.EncodeToString(t.secret))
}

// session stored in Redis, encrypted with the *ticket* secret (not the cookie secret)
func (t *ticket) saveSession(s *sessions.SessionState, saver saveFunc) error {
    c, err := encryption.NewGCMCipher(t.secret)  // GCM, not CFB
    // ...
    ciphertext, err := s.EncodeSessionState(c, false)  // msgpack, NO lz4
    return saver(t.id, ciphertext, t.options.Expire)
}
```

This is a completely different format from the cookie session:

| | Cookie session | Redis session (ticket) |
|---|---|---|
| Cipher | AES-CFB | AES-128-GCM |
| Key | cookie secret (raw string) | per-session ticket secret |
| Serialization | msgpack | msgpack |
| Compression | lz4 | **none** |
| Storage | in the cookie | Redis, keyed by ticket ID |
| Revocable | no | yes |

I rewrote the session creation to generate a random ticket ID and secret, encrypt the msgpack session with AES-GCM using the ticket secret, store it in Redis, and set the signed ticket reference as the `_oauth2_proxy` cookie.

I stored the ticket ID alongside the `qr_session` in Redis:

```json
{
  "email": "user@example.com",
  "username": "username",
  "access_token": "...",
  "oauth2_ticket_id": "_oauth2_proxy-eeeb18501625dee77f344c0a6193d0bc"
}
```

End Session now does two Redis deletes:

```go
func handleLogout(w http.ResponseWriter, r *http.Request) {
    sessionID := r.FormValue("session_id")
    ctx := r.Context()
    if raw, err := rdb.Get(ctx, "session:"+sessionID).Result(); err == nil {
        var sd sessionData
        if json.Unmarshal([]byte(raw), &sd) == nil && sd.OAuth2TicketID != "" {
            rdb.Del(ctx, sd.OAuth2TicketID)  // kills oauth2-proxy session
        }
    }
    rdb.Del(ctx, "session:"+sessionID)  // kills qr session
}
```

I configured oauth2-proxy to use Redis session storage pointing at the same Redis instance, added the Cilium network policy to allow ingress from the oauth2-proxy namespace, and removed the Homer proxy from `qr.hippotion.com` — it was no longer needed.

One final gotcha: `session_store_type = "redis"` in oauth2-proxy's legacy config file does nothing. There's no error, no warning. It silently ignores the option. The flag only works when passed as an actual CLI argument via `extraArgs` in the Helm chart values:

```yaml
extraArgs:
  session-store-type: redis
  redis-connection-url: "redis://qr-auth-redis:6379"
```

After that, End Session worked correctly. Phone taps the button, ticket is deleted from Redis, the next ForwardAuth request for any app on the domain immediately redirects to the QR lock screen.

---

## What the final architecture looks like

```
Phone: scan QR
  → /device?token=xxx → intermediate page ("Continue with GitLab")
  → GitLab OAuth on phone (already logged in → direct callback)
  → /callback: exchange code → get email + access token
  → create Redis ticket: AES-128-GCM(msgpack(session), ticketSecret)
  → store ticket in Redis at "_oauth2_proxy-<hex>"
  → mark device token as authed, store ticketID in qr session

TV: poll fires
  → read qr session from Redis (has email, accessToken, ticketID)
  → set _oauth2_proxy cookie: signed ticket reference
  → set qr_session cookie
  → redirect to home.hippotion.com

Any protected app (home, argo, grafana, ...):
  → Traefik ForwardAuth → oauth2-proxy
  → oauth2-proxy reads _oauth2_proxy cookie → decodes ticket
  → looks up "_oauth2_proxy-<hex>" in Redis → decrypts session
  → validates email, access token → 200 OK

Phone: "End Session"
  → POST /logout with session_id
  → delete "session:<id>" from Redis (qr session gone)
  → delete "_oauth2_proxy-<hex>" from Redis (oauth2 ticket gone)
  → next ForwardAuth on TV: Redis lookup fails → redirect to login
```

The intermediate page on the phone ("Continue with GitLab" button instead of auto-redirect) was an unexpected requirement. Mobile browsers opened by the camera app often don't share sessions with the browser where GitLab is logged in. When you auto-redirect to GitLab in a browser with no existing session, GitLab redirects to the sign-in page. The OAuth state is stored in a session cookie that GitLab sets during the initial authorize request. On mobile, the sign-in form submission can lose this cookie due to SameSite restrictions — after sign-in, GitLab can't resume the OAuth flow and falls back to `/users/sign_in` with no further redirect. The intermediate page gives the user a visible moment to confirm they're in a browser with an active GitLab session before initiating the OAuth redirect.

---

## Lessons

**Read the source, not the docs.** The docs say "AES encryption" without specifying the mode or how the key is derived. The source has the answer in twenty lines.

**Test at the boundary.** The curl test against the ForwardAuth endpoint was the most valuable debugging step. It isolated exactly which layer was failing and gave me the real error message instead of a browser redirect loop. Without it, I'd still be guessing.

**Format assumptions are fragile.** I assumed JSON because JSON is the default for everything. oauth2-proxy uses MessagePack because it produces smaller cookies. LZ4 because it decompresses fast. AES-CFB because that's what was chosen when the code was written. None of this is unreasonable, but none of it is obvious from the outside.

**Two formats, same codebase.** Cookie sessions and Redis ticket sessions use different ciphers, different compression, different key derivation. The GCM cipher I found first is correct — but for Redis sessions, not cookie sessions. The CFB cipher is for cookie sessions. I had the right code in the wrong place.

**Config files can silently ignore options.** `session_store_type = "redis"` in oauth2-proxy's legacy config file does nothing. `--session-store-type=redis` on the command line works. No error, no warning, no indication that the option was parsed but not applied.

**Revocability requires server-side state.** A self-contained encrypted cookie cannot be revoked without adding a denylist (which has its own scaling problems). If you need End Session to mean something, you need a server-side session store. oauth2-proxy supports Redis sessions precisely for this reason — the ticket design is clean and the revocation path is a single Redis delete.

The code is at [github.com/janos-gyorgy/qr-device-login](https://github.com/janos-gyorgy/qr-device-login).
