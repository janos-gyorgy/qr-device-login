# qr-device-login

A small Go service that lets you log in to a PC browser by scanning a QR code on your phone.

The PC shows a QR code. You scan it with your phone, complete GitLab OAuth there, and the PC session unlocks — no typing on the PC required. Works alongside [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy): after QR login, all oauth2-proxy-protected apps on the same domain are accessible without a separate login prompt.

## How it works

```
PC browser                    qr-device-login             Phone browser
    |                               |                           |
    |-- GET /                       |                           |
    |<-- QR code page (polls /poll) |                           |
    |                               |                           |
    |                   (scan QR code)                          |
    |                               |<-- GET /device?token=...  |
    |                               |--- redirect to GitLab --> |
    |                               |                           |-- GitLab OAuth -->
    |                               |<-- GET /callback?code=... |
    |                               |--- "Screen unlocked" ---> |
    |                               |                           |
    |<-- /poll returns authed ------| (sets session cookies)    |
    |--- redirect to home ----------|                           |
```

The device token is single-use and expires in 5 minutes. The phone gets an "End Session" button that invalidates the server-side session immediately.

## Requirements

- GitLab OAuth application (gitlab.com or self-managed)
- Redis (ephemeral, no persistence needed)
- oauth2-proxy deployed on the same cookie domain (optional but recommended — see [Cookie integration](#cookie-integration))

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
| `POST_LOGIN_URL` | no | Where to redirect the PC after successful auth (default: `https://home.yourdomain.com`) |
| `COOKIE_DOMAIN` | no | Cookie domain scope (default: `.yourdomain.com`) |
| `OAUTH2_PROXY_COOKIE_SECRET` | no | See [Cookie integration](#cookie-integration) |

## GitLab OAuth app setup

1. Go to `https://gitlab.com/-/profile/applications`
2. Create a new application:
   - **Name:** anything
   - **Redirect URI:** `https://qr.yourdomain.com/callback`
   - **Scopes:** `read_user`, `openid`
3. Copy the Application ID and Secret into `GITLAB_CLIENT_ID` / `GITLAB_CLIENT_SECRET`

## Cookie integration

If you run oauth2-proxy on the same domain, set `OAUTH2_PROXY_COOKIE_SECRET` to the same value as oauth2-proxy's `--cookie-secret`. After QR login, the service sets a valid `_oauth2_proxy` session cookie so all protected apps on the domain work immediately — no second login needed.

The cookie secret must be the same value oauth2-proxy is using. If you generated it with `openssl rand -base64 24`, store and pass that base64 string as-is.

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

See [`k8s/`](k8s/) for example manifests. The example uses a Redis sidecar in the same namespace and a Traefik IngressRoute, but the service itself has no hard dependency on either — any reverse proxy and any Redis-compatible store will work.

## Building

```bash
go build -o qr-device-login .

# or with Docker
docker build -t qr-device-login:latest .
```

## License

MIT — see [LICENSE](LICENSE)
