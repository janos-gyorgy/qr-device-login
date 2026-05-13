# qr-device-login

A small Go service that lets you log in to a PC browser by scanning a QR code on your phone.

The PC shows a QR code. You scan it with your phone, complete GitLab OAuth there, and the PC session unlocks — no typing on the PC required. Works alongside [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy): after QR login, all oauth2-proxy-protected apps on the same domain are accessible without a separate login prompt. End Session on the phone immediately revokes access to all of them.

## How it works

<img width="1536" height="1024" alt="QR2" src="https://github.com/user-attachments/assets/c8103454-b7e1-4023-be36-da58f2379635" />

1. PC opens `qr.yourdomain.com` — a QR code is shown, the page polls for authentication
2. Phone scans the QR code, opens the device page, taps **Continue with GitLab**
3. Phone completes GitLab OAuth
4. Server marks the session as authenticated, creates a Redis-backed oauth2-proxy session ticket
5. PC's poll returns success, sets `_oauth2_proxy` session cookie, redirects to your home URL
6. All oauth2-proxy-protected apps on the domain are immediately accessible
7. Phone shows **End Session** button — tapping it deletes the session from Redis, immediately revoking access everywhere

The device token is single-use and expires in 5 minutes. Sessions are stored in Redis and can be revoked instantly.

## Requirements

- GitLab OAuth application (gitlab.com or self-managed)
- Redis (ephemeral, no persistence needed)
- oauth2-proxy configured with Redis session storage (see [oauth2-proxy integration](#oauth2-proxy-integration))

## Configuration

All configuration is via environment variables.

| Variable | Required | Description |
|---|---|---|
| `GITLAB_CLIENT_ID` | yes | GitLab OAuth application ID |
| `GITLAB_CLIENT_SECRET` | yes | GitLab OAuth application secret |
| `GITLAB_REDIRECT_URI` | yes | Must match the callback URL registered in GitLab (`https://qr.yourdomain.com/callback`) |
| `ALLOWED_EMAIL` | yes | Single email address permitted to log in |
| `PUBLIC_URL` | yes | Base URL of this service (`https://qr.yourdomain.com`) |
| `REDIS_ADDR` | no | Redis address (default: `localhost:6379`) |
| `POST_LOGIN_URL` | no | Where to redirect the PC after successful auth (default: `/`) |
| `COOKIE_DOMAIN` | no | Cookie domain scope (default: empty) |
| `OAUTH2_PROXY_COOKIE_SECRET` | no | See [oauth2-proxy integration](#oauth2-proxy-integration) |

## GitLab OAuth app setup

1. Go to `https://gitlab.com/-/profile/applications`
2. Create a new application:
   - **Redirect URI:** `https://qr.yourdomain.com/callback`
   - **Scopes:** `read_user`
3. Copy the Application ID and Secret into `GITLAB_CLIENT_ID` / `GITLAB_CLIENT_SECRET`

**Note on mobile browsers:** When the phone scans the QR code, it opens the device page in whichever browser the camera uses. If GitLab is not already logged in in that browser, an intermediate page is shown with a "Continue with GitLab" button — this gives you a chance to be in the right browser before the OAuth redirect starts. Direct auto-redirect causes GitLab to lose the OAuth state during the sign-in flow on mobile.

## oauth2-proxy integration

This is where the interesting part lives. When `OAUTH2_PROXY_COOKIE_SECRET` is set, qr-device-login creates a proper oauth2-proxy persistence ticket in Redis and sets the `_oauth2_proxy` session cookie. After QR login, all apps on the domain that use oauth2-proxy ForwardAuth work without a second login prompt.

**For End Session to revoke access immediately** (not just expire after a timeout), oauth2-proxy must be configured to use Redis session storage pointing at the same Redis instance:

```
--session-store-type=redis
--redis-connection-url=redis://your-redis:6379
```

Without Redis sessions on the oauth2-proxy side, End Session still works for the QR page itself but the `_oauth2_proxy` cookie in the browser remains valid until it naturally expires.

`OAUTH2_PROXY_COOKIE_SECRET` must be the same value as oauth2-proxy's `--cookie-secret`. If generated with `openssl rand -base64 24`, pass that base64 string as-is.

### How the session ticket works

qr-device-login replicates oauth2-proxy v7's persistence ticket format exactly:
- Generates a random ticket ID (`_oauth2_proxy-<hex>`) and a 16-byte per-session AES key
- Encrypts the session state (msgpack-encoded, no compression) with AES-128-GCM using the ticket key
- Stores the encrypted session in Redis under the ticket ID
- Signs the ticket string (`v2.<ticketID_b64>.<ticketKey_b64>`) using oauth2-proxy's HMAC format
- Sets the signed ticket as the `_oauth2_proxy` cookie

This matches oauth2-proxy v7.15 exactly. When End Session is called, both the qr session and the oauth2-proxy ticket are deleted from Redis — the next ForwardAuth request for any app will immediately fail and redirect to login.

## Running locally

```bash
docker run -d --name redis redis:7-alpine --save "" --appendonly no

docker run \
  -e GITLAB_CLIENT_ID=your-client-id \
  -e GITLAB_CLIENT_SECRET=your-client-secret \
  -e GITLAB_REDIRECT_URI=https://qr.yourdomain.com/callback \
  -e ALLOWED_EMAIL=you@example.com \
  -e PUBLIC_URL=https://qr.yourdomain.com \
  -e REDIS_ADDR=redis:6379 \
  --link redis \
  -p 8080:8080 \
  ghcr.io/janos-gyorgy/qr-device-login:latest
```

## Kubernetes deployment

See [`k8s/`](k8s/) for example manifests. Configure your oauth2-proxy deployment to use the same Redis:

```yaml
# add to your oauth2-proxy deployment args
- --session-store-type=redis
- --redis-connection-url=redis://qr-device-login-redis:6379
```

## Building

```bash
go build -o qr-device-login .

# or with Docker
docker build -t qr-device-login:latest .
```

## License

MIT — see [LICENSE](LICENSE)
