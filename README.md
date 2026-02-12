OAuth2 PAM module
=================

This PAM module enables login with OAuth2/OIDC JWT tokens instead of passwords. It validates tokens locally using JWKS (JSON Web Key Sets) fetched from the OIDC issuer's discovery endpoint.

## How to install it:

### Dependencies

```bash
# Debian/Ubuntu
sudo apt-get install libjwt-dev libjansson-dev libcurl4-openssl-dev libssl-dev libpam-dev

# RHEL/CentOS (EPEL required)
sudo yum install epel-release && sudo yum install libjwt-devel jansson-devel libcurl-devel openssl-devel pam-devel
```

### Build

```bash
make
sudo make install
```

## Configuration

```
auth sufficient pam_oauth2.so <issuer_url> <login_field> [claim=value]... [ttl=SECONDS] [debug]
account sufficient pam_oauth2.so
```

| Argument | Required | Description |
|----------|----------|-------------|
| `issuer_url` | Yes | OIDC issuer URL, e.g. `https://login.example.com` |
| `login_field` | Yes | JWT claim matched against PAM username, e.g. `sub`, `email` |
| `claim=value` | No | Additional claim checks, e.g. `aud=myapp`, `scope=openid` |
| `ttl=SECONDS` | No | JWKS cache TTL in seconds (default: 1296000 = 15 days) |
| `debug` | No | Enable verbose debug logging to syslog |

## How it works

Suppose the configuration looks like:

```
auth sufficient pam_oauth2.so https://login.example.com sub aud=myapp ttl=1296000 debug
```

And somebody is trying to login with login=foo and a JWT token as the password.

pam\_oauth2 will:

1. Fetch the OIDC discovery document from `https://login.example.com/.well-known/openid-configuration`
2. Extract the `jwks_uri` and fetch the JSON Web Key Set (JWKS)
3. Cache the JWKS locally at `/var/cache/pam_oauth2/<hash>/` with the configured TTL
4. Parse the JWT header to find the signing key ID (`kid`) and algorithm (`alg`)
5. Find the matching public key in the cached JWKS
6. Verify the JWT signature using the public key
7. Validate claims:
   - `iss` matches the configured issuer URL
   - `exp` has not passed (token not expired)
   - `sub` (the login\_field) matches the PAM username `foo`
   - `aud` equals `myapp` (the configured claim check)

If any step fails, authentication is denied.

### JWKS Caching

JWKS keys are cached on disk at `/var/cache/pam_oauth2/<sha256-of-issuer-url>/`. The cache is refreshed when older than the configured TTL (default 15 days). If a refresh fails but a stale cache exists, the stale cache is used as a fallback (with a syslog warning).

### Debug mode

When `debug` is specified, detailed step-by-step logging is written to syslog including cache hit/miss status, discovery URLs, key counts, algorithm info, and claim comparisons. Token values and key material are never logged.

### Supported Algorithms

RS256, RS384, RS512, ES256, ES384, ES512. HMAC algorithms and `alg: "none"` are rejected.



