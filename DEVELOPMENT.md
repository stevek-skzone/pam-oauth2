# Developer Guide

Detailed implementation reference for `pam-oauth2`. Written for developers who may not be familiar with C, PAM, or the cryptographic libraries used here.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [How PAM Modules Work](#how-pam-modules-work)
- [Authentication Flow (Step by Step)](#authentication-flow-step-by-step)
- [File-by-File Walkthrough](#file-by-file-walkthrough)
  - [pam_oauth2.c - Entry Point and Config Parsing](#pam_oauth2c---entry-point-and-config-parsing)
  - [oidc.c - OIDC Discovery and JWKS Caching](#oidcc---oidc-discovery-and-jwks-caching)
  - [jwt_verify.c - JWT Signature Verification and Claims](#jwt_verifyc---jwt-signature-verification-and-claims)
- [Key C Patterns Used](#key-c-patterns-used)
- [Library Reference](#library-reference)
- [Build System](#build-system)
- [Debugging](#debugging)
- [Testing](#testing)
- [Common Pitfalls](#common-pitfalls)

---

## Architecture Overview

The module is split into three compilation units with clear responsibilities:

```
pam_oauth2.c          oidc.c                jwt_verify.c
+-----------------+   +-------------------+  +---------------------+
| PAM interface   |   | HTTP fetching     |  | Base64url decoding  |
| Config parsing  |-->| OIDC discovery    |  | JWT header parsing  |
| Orchestration   |   | JWKS caching      |  | JWKS key lookup     |
+-----------------+   | Filesystem I/O    |  | JWK-to-PEM convert  |
                      +-------------------+  | Signature verify    |
                                             | Claims validation   |
                                             +---------------------+
```

Data flows left to right: `pam_oauth2.c` calls `oidc.c` to get JWKS keys, then calls `jwt_verify.c` to validate the token. The two utility modules have no knowledge of each other.

### Why Three Files?

- **Testability** - `oidc.c` can be tested against real OIDC providers without any JWT logic. `jwt_verify.c` can be tested with static JWKS files without any network.
- **Separation of concerns** - Network/cache code is isolated from cryptographic code. A bug in HTTP handling can't accidentally affect signature verification.
- **Readability** - Each file stays under 350 lines.

---

## How PAM Modules Work

PAM (Pluggable Authentication Modules) is the standard authentication framework on Linux. When a user logs in via SSH, `sudo`, or any PAM-aware application, the system loads shared library files (`.so`) from `/lib/security/` based on config files in `/etc/pam.d/`.

### The Contract

A PAM module must export specific C functions. The system calls them and inspects their integer return values:

| Function | Purpose | Our Return |
|----------|---------|------------|
| `pam_sm_authenticate` | Verify the user's identity | The real logic lives here |
| `pam_sm_setcred` | Set/refresh credentials | `PAM_CRED_UNAVAIL` (stub) |
| `pam_sm_acct_mgmt` | Check if account is valid | `PAM_SUCCESS` (stub) |
| `pam_sm_open_session` | Setup for session | `PAM_SUCCESS` (stub) |
| `pam_sm_close_session` | Teardown for session | `PAM_SUCCESS` (stub) |
| `pam_sm_chauthtok` | Change auth token (password) | `PAM_SUCCESS` (stub) |

Only `pam_sm_authenticate` does real work. The rest are stubs required by the PAM ABI.

### Return Codes That Matter

| Code | Meaning | When We Return It |
|------|---------|-------------------|
| `PAM_SUCCESS` | Authentication succeeded | All checks passed |
| `PAM_AUTH_ERR` | Authentication failed | Bad signature, expired token, claim mismatch |
| `PAM_USER_UNKNOWN` | User not found | The login_field claim is missing from the JWT |
| `PAM_AUTHINFO_UNAVAIL` | Cannot reach auth service | No JWKS available, no issuer configured |

### How PAM Passes Data to Us

The PAM config line:
```
auth sufficient pam_oauth2.so https://login.example.com sub aud=myapp debug
```

Gets split by PAM into:
- `argc = 4`
- `argv[0] = "https://login.example.com"`
- `argv[1] = "sub"`
- `argv[2] = "aud=myapp"`
- `argv[3] = "debug"`

We get the username and password (JWT token) from PAM via:
- `pam_get_user()` - returns the login name the user typed
- `pam_get_authtok()` - returns the "password" (in our case, the JWT token)

### The `(void)flags;` Pattern

```c
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)flags;  /* <-- This */
```

C compilers warn about unused parameters (`-Wextra`). Since PAM requires these exact function signatures but we don't use `flags`, `(void)flags` tells the compiler "I know this is unused, it's intentional." This avoids warnings without removing the parameter.

---

## Authentication Flow (Step by Step)

Here's what happens when someone types a JWT token as their password:

```
User types password (JWT token)
         |
         v
1. pam_sm_authenticate() called by PAM system
         |
    parse_config() extracts issuer_url, login_field, claims, ttl, debug
         |
    pam_get_user() --> "alice"
    pam_get_authtok() --> "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyJ9.eyJpc3..."
         |
         v
2. load_jwks_if_needed(issuer_url, ttl, debug)
         |
    SHA256("https://login.example.com") --> "a1b2c3d4..."
    Check /var/cache/pam_oauth2/a1b2c3d4.../metadata.json
         |
    +-- Cache fresh? --> Read /var/cache/.../jwks.json --> return JWKS
    |
    +-- Cache stale or missing?
         |
         GET https://login.example.com/.well-known/openid-configuration
         Parse JSON --> extract "jwks_uri"
         GET the jwks_uri
         Write jwks.json + metadata.json to cache
         |
         +-- Fetch failed + stale cache? --> Use stale cache (log warning)
         +-- Fetch failed + no cache? --> return NULL (PAM_AUTHINFO_UNAVAIL)
         |
         v
3. verify_and_check_claims(token, jwks_json, issuer, login_field, username, ...)
         |
    Split JWT on first '.' --> base64url-decode header
    Parse JSON header --> extract "kid" and "alg"
         |
    Reject if alg is "none", "HS256", "HS384", "HS512" (security)
         |
    Search JWKS "keys" array for matching "kid"
    (If no kid and exactly 1 key, use it)
         |
    Convert JWK to PEM:
      RSA: decode n,e --> BN_bin2bn --> RSA_set0_key --> PEM_write_bio_PUBKEY
      EC:  decode x,y --> BN_bin2bn --> EC_KEY_set_public_key --> PEM_write_bio_PUBKEY
         |
    jwt_decode(token, pem_key) --> verifies signature
         |
    Validate claims:
      iss == issuer_url?
      exp > now?
      login_field claim == "alice"?
      All extra claim=value pairs match?
         |
         v
4. Return PAM_SUCCESS or error code
```

---

## File-by-File Walkthrough

### pam_oauth2.c - Entry Point and Config Parsing

**~180 lines.** The simplest file. Parses config, gets user/token from PAM, calls the other two modules.

#### Config Struct

```c
struct pam_oauth2_config {
    const char *issuer_url;      /* argv[0]: "https://login.example.com" */
    const char *login_field;     /* argv[1]: "sub" */
    struct claim_check *claims;  /* argv[2..n]: dynamically allocated array */
    int num_claims;              /* Number of claim=value pairs */
    int ttl_seconds;             /* From "ttl=N", default 1296000 (15 days) */
    int debug;                   /* 1 if "debug" was in argv */
};
```

#### parse_config() - Two-Pass Parsing

The function iterates argv twice:

1. **First pass** (lines 39-46): Count how many `claim=value` pairs exist. This is needed because C requires knowing array size at allocation time (no dynamic arrays like Python/JS).

2. **Second pass** (lines 51-67): Actually parse each argument. For claim pairs like `aud=myapp`, we split on `=`:
   - `strndup(argv[i], eq - argv[i])` copies just `"aud"` (the part before `=`)
   - `eq + 1` points to `"myapp"` (the part after `=`, no copy needed since argv is stable)

Why `strndup` for the key? Because the key is embedded inside `"aud=myapp"` and we need a standalone null-terminated string `"aud"`. For the value, we can just point into the existing argv string since it's already null-terminated at the right place.

#### pam_sm_authenticate() - Orchestration

This function is just glue. It:
1. Parses config
2. Gets username and token from PAM
3. Calls `load_jwks_if_needed()` to get JWKS
4. Calls `verify_and_check_claims()` to validate the token
5. Cleans up and returns

The `goto cleanup` pattern (explained below) ensures `jwks_json` and config memory are always freed.

---

### oidc.c - OIDC Discovery and JWKS Caching

**~330 lines.** Handles all HTTP and filesystem operations. Has no knowledge of JWT format or cryptography.

#### http_get() - Fetching URLs with libcurl

libcurl is the standard C HTTP library. It uses a callback-based model (because C has no built-in async/await or string streams):

```c
/* libcurl calls this function repeatedly with chunks of downloaded data */
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct http_response *resp = userdata;
    size_t data_size = size * nmemb;
    char *new_data = realloc(resp->data, resp->len + data_size + 1);
    /* ... append chunk to growing buffer ... */
}
```

Think of it like a streaming reader. As data arrives from the network, libcurl calls our `write_callback` with each chunk. We grow a buffer (`realloc`) and append each chunk. The `+1` is for the null terminator that C strings require.

**HTTPS enforcement**: Line 48 checks that the URL starts with `https://`. This is a security measure -- we never send requests over plain HTTP since we're fetching cryptographic keys.

**Curl options explained**:
- `CURLOPT_CONNECTTIMEOUT, 30L` - Give up connecting after 30 seconds
- `CURLOPT_TIMEOUT, 60L` - Give up on the entire request after 60 seconds
- `CURLOPT_FOLLOWLOCATION, 1L` - Follow HTTP redirects (common in OIDC setups)
- `CURLOPT_USERAGENT` - Identify ourselves; some servers reject requests without a User-Agent

#### compute_cache_path() - Deterministic Cache Directory

We need a filesystem-safe directory name for each issuer URL. `SHA256("https://login.example.com")` gives us a fixed-length hex string like `a1b2c3d4e5f6...`. The cache path becomes `/var/cache/pam_oauth2/a1b2c3d4e5f6.../`.

The OpenSSL EVP (Envelope) API for hashing:
```c
EVP_MD_CTX *ctx = EVP_MD_CTX_new();        /* Create a hash context */
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL); /* Initialize for SHA-256 */
EVP_DigestUpdate(ctx, data, data_len);      /* Feed in the data */
EVP_DigestFinal_ex(ctx, hash, &hash_len);   /* Get the digest */
EVP_MD_CTX_free(ctx);                       /* Free the context */
```

This is like Python's `hashlib.sha256(data).hexdigest()` but spread across multiple calls. The "EVP" prefix stands for "Envelope" and is OpenSSL's high-level API that works with any hash algorithm.

#### Cache Structure

```
/var/cache/pam_oauth2/
  <sha256-hex>/
    jwks.json         # The raw JWKS from the OIDC provider (mode 0600)
    metadata.json     # {"fetched_at": 1706000000} (mode 0600)
```

Permissions: Directory is 0700 (owner rwx only), files are 0600 (owner rw only). Since PAM modules run as root, this means only root can read the cached keys.

#### load_jwks_if_needed() - Cache Logic

This is the top-level function. The decision tree:

```
Is (now - fetched_at) <= ttl?
  YES --> return cached jwks.json (fast path, no network)
  NO or no cache -->
    Try to fetch fresh JWKS from issuer
      Success --> write cache, return fresh JWKS
      Failure -->
        Stale cache exists? --> use it (log warning)
        No cache at all? --> return NULL (auth fails with PAM_AUTHINFO_UNAVAIL)
```

The stale cache fallback is important for resilience. If the OIDC provider is temporarily down, cached keys are likely still valid (RSA keys typically rotate monthly or less).

#### mkdir_p() - Recursive Directory Creation

This mimics `mkdir -p /var/cache/pam_oauth2/abc123`. C's `mkdir()` can only create one directory level at a time, so we walk the path and create each component:

```c
"/var/cache/pam_oauth2/abc123"
  ^-- mkdir "/var"          (EEXIST, ok)
  ^-- mkdir "/var/cache"    (EEXIST, ok)
  ^-- mkdir "/var/cache/pam_oauth2"  (created or EEXIST)
  ^-- mkdir "/var/cache/pam_oauth2/abc123"  (created)
```

#### JSON Handling with Jansson

Jansson is the JSON library. Key patterns:

```c
/* Parse JSON string into an object tree */
json_t *root = json_loads(json_string, 0, &err);

/* Get a value from an object (does NOT transfer ownership) */
json_t *value = json_object_get(root, "key_name");

/* Check type and extract value */
if (json_is_string(value))
    const char *str = json_string_value(value);
if (json_is_integer(value))
    long num = json_integer_value(value);

/* CRITICAL: Release the root when done (decrements reference count) */
json_decref(root);
```

Jansson uses **reference counting**. `json_object_get()` returns a *borrowed reference* (you don't need to free it, but it becomes invalid when the parent is freed). `json_deep_copy()` creates an independent copy with its own reference count. This is why `find_key_in_jwks()` deep-copies the matched key before freeing the JWKS root.

---

### jwt_verify.c - JWT Signature Verification and Claims

**~470 lines.** The most complex file. Handles all cryptographic operations.

#### base64url_decode() - JWT's Encoding Format

JWTs use "base64url" encoding, which is slightly different from standard base64:

| Standard Base64 | Base64url |
|----------------|-----------|
| `+` | `-` |
| `/` | `_` |
| `=` padding required | No padding |

Our decoder:
1. Replaces `-` with `+` and `_` with `/`
2. Adds `=` padding to make the length a multiple of 4
3. Calls OpenSSL's `EVP_DecodeBlock()` to do the actual decoding

```c
/* Why subtract pad from the output length? */
*out_len = EVP_DecodeBlock(decoded, b64, len + pad);
*out_len -= pad;
```

`EVP_DecodeBlock` returns the raw decoded byte count as if all input was data. But the `=` padding characters we added represent "no data" bytes, so we subtract them to get the actual content length.

#### parse_jwt_header() - Anatomy of a JWT

A JWT has three dot-separated parts: `HEADER.PAYLOAD.SIGNATURE`

```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOi...payload....signature
^---- header (base64url) ----^
```

We only need the header at this stage (to find `kid` and `alg`). The full token is passed to `jwt_decode()` later for signature verification.

```c
const char *dot = strchr(token, '.');   /* Find first '.' */
header_b64 = strndup(token, dot - token); /* Copy just the header part */
header_json = base64url_decode(header_b64, &decoded_len);
/* header_json is now: {"alg":"RS256","kid":"abc123","typ":"JWT"} */
```

#### is_allowed_algorithm() - Preventing Algorithm Confusion Attacks

This is a critical security function. JWT supports multiple algorithms:

- **RS256/384/512** - RSA signature (asymmetric, safe for our use)
- **ES256/384/512** - ECDSA signature (asymmetric, safe for our use)
- **HS256/384/512** - HMAC (symmetric, **dangerous** if you have the public key)
- **none** - No signature at all (**always dangerous**)

The "algorithm confusion" attack: An attacker takes an RS256-signed JWT, changes the algorithm to HS256, then signs it using the RSA *public* key as the HMAC secret. If the server naively accepts this, the forged token verifies successfully because the public key is... public.

By allowlisting only asymmetric algorithms, this attack is impossible.

#### find_key_in_jwks() - Key Selection

A JWKS (JSON Web Key Set) typically looks like:

```json
{
  "keys": [
    {"kty":"RSA", "kid":"key1", "n":"0vx7...", "e":"AQAB", ...},
    {"kty":"RSA", "kid":"key2", "n":"xNnP...", "e":"AQAB", ...}
  ]
}
```

The `kid` (Key ID) in the JWT header tells us which key to use. OIDC providers rotate keys and may have multiple active keys at once. If the JWT has no `kid` (some simple setups), we accept a single-key JWKS as a fallback.

The function returns a `json_deep_copy()` of the matched key. This is because we free the JWKS root object at the end of the function, but the caller needs the key object to remain valid.

#### rsa_jwk_to_pem() - Converting JWKS RSA Keys

This is the most intricate function. It converts a JWK key (JSON with base64url-encoded numbers) into PEM format (the text format OpenSSL and libjwt understand).

**What's in a JWK RSA key?**
- `n` - The RSA modulus (a very large number, ~256 bytes for RSA-2048)
- `e` - The public exponent (usually 65537, encoded as `AQAB`)

**What's PEM format?**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
(base64-encoded DER/ASN.1 structure)
-----END PUBLIC KEY-----
```

**The conversion pipeline:**

```
JWK "n" (base64url string)
    |  base64url_decode()
    v
Raw bytes (unsigned char*)
    |  BN_bin2bn()
    v
OpenSSL BIGNUM (arbitrary-precision integer)
    |  RSA_set0_key(rsa, n_bn, e_bn, NULL)
    v
OpenSSL RSA struct (contains the public key components)
    |  EVP_PKEY_assign_RSA(pkey, rsa)
    v
OpenSSL EVP_PKEY (generic key wrapper)
    |  PEM_write_bio_PUBKEY(bio, pkey)
    v
PEM string in a BIO (memory buffer)
    |  BIO_get_mem_data() + strndup()
    v
PEM string (char*) ready for libjwt
```

**Ownership transfers** are critical here:

```c
RSA_set0_key(rsa, n_bn, e_bn, NULL);
n_bn = NULL;  /* RSA now owns these BIGNUMs */
e_bn = NULL;  /* Setting to NULL prevents double-free in cleanup */

EVP_PKEY_assign_RSA(pkey, rsa);
rsa = NULL;   /* EVP_PKEY now owns the RSA struct */
```

When you call `RSA_set0_key()`, the RSA object takes ownership of the BIGNUM pointers. If we later called `BN_free(n_bn)` AND `RSA_free(rsa)`, the BIGNUM would be freed twice (crash). Setting the pointer to NULL means the cleanup block's `BN_free(NULL)` is a no-op (safe by design in OpenSSL).

#### ec_jwk_to_pem() - Converting JWKS EC Keys

Same concept as RSA but for elliptic curve keys:

- `crv` - Curve name: "P-256", "P-384", or "P-521"
- `x`, `y` - The point coordinates on the curve

The curve name maps to an OpenSSL NID (Numeric IDentifier):
```c
"P-256" --> NID_X9_62_prime256v1  (also called secp256r1)
"P-384" --> NID_secp384r1
"P-521" --> NID_secp521r1         (note: 521, not 512)
```

#### verify_and_check_claims() - The Main Pipeline

This is the top-level orchestrator for `jwt_verify.c`. It chains together all the steps:

```c
parse_jwt_header()    --> kid, alg
is_allowed_algorithm()  --> security check
find_key_in_jwks()    --> matched JWK
jwks_key_to_pem()     --> PEM string
jwt_decode()          --> signature verification (libjwt)
jwt_get_alg()         --> defense-in-depth algorithm check
validate_claims()     --> iss, exp, login_field, extra claims
```

If any step fails, we `goto cleanup` which frees everything and returns the error code.

#### validate_claims() - Checking JWT Contents

After signature verification, we check the token's claims (payload fields):

1. **Issuer (`iss`)**: Must exactly match the configured issuer URL. This prevents tokens from Provider A being used at Provider B.

2. **Expiration (`exp`)**: Unix timestamp that must be in the future. The `errno` check handles the case where `exp` is missing entirely:
   ```c
   errno = 0;
   exp_val = jwt_get_grant_int(jwt, "exp");
   if (errno == ENOENT) { /* "exp" claim doesn't exist at all */ }
   ```

3. **Login field**: The configured claim (e.g., `sub`) must match the PAM username.

4. **Additional claims**: Each `claim=value` from the PAM config is checked as a string match.

---

## Key C Patterns Used

### The `goto cleanup` Pattern

C has no destructors, try/finally, or defer. The `goto cleanup` pattern ensures all resources are freed on every code path:

```c
int do_something(void) {
    int result = ERROR;
    char *a = NULL, *b = NULL;

    a = malloc(100);
    if (!a)
        goto cleanup;    /* Jumps to cleanup, frees nothing (a and b are NULL) */

    b = malloc(200);
    if (!b)
        goto cleanup;    /* Jumps to cleanup, frees a (b is NULL, free(NULL) is safe) */

    /* ... do work ... */
    result = SUCCESS;

cleanup:
    free(b);             /* safe even if b is NULL */
    free(a);
    return result;
}
```

This is the C equivalent of Python's `try/finally` or Go's `defer`. It's widely used in the Linux kernel, OpenSSL, and most C system software. The key rules:

1. Initialize all pointers to `NULL` at declaration
2. On any error, `goto cleanup`
3. The cleanup block checks for NULL before freeing (or relies on `free(NULL)` being safe per the C standard)

### `static` Functions

```c
static char *http_get(const char *url, int debug)
```

The `static` keyword on a function means "only visible within this file." This is C's equivalent of Python's underscore convention (`_private_method`) but enforced by the compiler. Only non-static functions (like `load_jwks_if_needed` and `verify_and_check_claims`) are callable from other files.

### Pointer Arithmetic for String Splitting

```c
const char *eq = strchr(argv[i], '=');
/* argv[i] = "aud=myapp" */
/* eq points to:    ^     */
/* eq - argv[i] = 3 (length of "aud") */
/* eq + 1 points to: ^    ("myapp") */
strndup(argv[i], eq - argv[i]);  /* copies "aud" */
```

In C, strings are just pointers to char arrays. `eq - argv[i]` gives the byte distance between two pointers, which equals the string length before `=`. `strndup()` copies exactly that many characters into a new null-terminated string.

### `const char *` vs `char *`

- `const char *` means "pointer to characters I promise not to modify." Used for function parameters that only read strings.
- `char *` means "pointer to characters I might modify" or "memory I own and must free."

When we store `config->claims[i].value = eq + 1`, we point into PAM's argv string (which we don't own and must not free). When we store `config->claims[i].key = strndup(...)`, we own that memory and must free it later. This is why `free_config()` frees keys but not values.

---

## Library Reference

### libcurl (curl/curl.h)

HTTP client library. Used only in `oidc.c`.

| Function | Purpose |
|----------|---------|
| `curl_easy_init()` | Create a session handle |
| `curl_easy_setopt()` | Configure the request (URL, callbacks, timeouts) |
| `curl_easy_perform()` | Execute the request (blocking) |
| `curl_easy_getinfo()` | Get response metadata (HTTP status code) |
| `curl_easy_cleanup()` | Free the session handle |

### Jansson (jansson.h)

JSON parser. Used in both `oidc.c` and `jwt_verify.c`.

| Function | Purpose |
|----------|---------|
| `json_loads(str, flags, &err)` | Parse JSON string into object tree |
| `json_load_file(path, flags, &err)` | Parse JSON file |
| `json_dump_file(root, path, flags)` | Write object tree to file |
| `json_object_get(obj, key)` | Get value by key (borrowed reference) |
| `json_array_get(arr, index)` | Get element by index (borrowed reference) |
| `json_array_size(arr)` | Get array length |
| `json_is_string(val)` | Type check |
| `json_is_integer(val)` | Type check |
| `json_is_array(val)` | Type check |
| `json_string_value(val)` | Extract C string (borrowed pointer) |
| `json_integer_value(val)` | Extract integer |
| `json_object()` | Create empty object |
| `json_object_set_new(obj, key, val)` | Add key-value (transfers ownership of val) |
| `json_integer(n)` | Create integer value |
| `json_deep_copy(val)` | Create independent copy |
| `json_decref(val)` | Decrement reference count (frees if zero) |

**Memory rule**: `json_object_get` and `json_array_get` return borrowed references; don't `json_decref` them. Only decref the root object and any deep copies you made.

### libjwt (jwt.h)

JWT creation, parsing, and verification.

| Function | Purpose |
|----------|---------|
| `jwt_decode(&jwt, token, key, key_len)` | Parse and verify JWT. Returns 0 on success. |
| `jwt_get_alg(jwt)` | Get algorithm enum from decoded JWT |
| `jwt_get_grant(jwt, name)` | Get string claim (returns NULL if missing) |
| `jwt_get_grant_int(jwt, name)` | Get integer claim (sets errno=ENOENT if missing) |
| `jwt_free(jwt)` | Free decoded JWT object |

`jwt_decode()` does the heavy lifting: it parses the JWT, verifies the signature against the provided PEM key, and makes claims accessible via `jwt_get_grant*()`.

### OpenSSL

Used for SHA256 hashing (cache paths), base64 decoding, and JWK-to-PEM key conversion.

**Hashing (EVP_MD)**:
| Function | Purpose |
|----------|---------|
| `EVP_MD_CTX_new()` | Create hash context |
| `EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)` | Initialize for SHA-256 |
| `EVP_DigestUpdate(ctx, data, len)` | Feed data |
| `EVP_DigestFinal_ex(ctx, hash, &len)` | Get final hash |
| `EVP_MD_CTX_free(ctx)` | Free context |

**Base64**:
| Function | Purpose |
|----------|---------|
| `EVP_DecodeBlock(out, in, in_len)` | Decode base64 to raw bytes |

**Big Numbers (BIGNUM)**:
| Function | Purpose |
|----------|---------|
| `BN_bin2bn(bytes, len, NULL)` | Convert raw bytes to arbitrary-precision integer |
| `BN_free(bn)` | Free a BIGNUM |

**RSA**:
| Function | Purpose |
|----------|---------|
| `RSA_new()` | Create empty RSA key struct |
| `RSA_set0_key(rsa, n, e, d)` | Set key components (transfers ownership) |
| `RSA_free(rsa)` | Free RSA key |

**EC**:
| Function | Purpose |
|----------|---------|
| `EC_KEY_new_by_curve_name(nid)` | Create EC key for a specific curve |
| `EC_KEY_set_public_key_affine_coordinates(ec, x, y)` | Set the public point |
| `EC_KEY_free(ec)` | Free EC key |

**EVP_PKEY (generic key wrapper)**:
| Function | Purpose |
|----------|---------|
| `EVP_PKEY_new()` | Create empty key wrapper |
| `EVP_PKEY_assign_RSA(pkey, rsa)` | Wrap RSA key (transfers ownership) |
| `EVP_PKEY_assign_EC_KEY(pkey, ec)` | Wrap EC key (transfers ownership) |
| `EVP_PKEY_free(pkey)` | Free key (and owned RSA/EC key) |

**BIO (I/O abstraction)**:
| Function | Purpose |
|----------|---------|
| `BIO_new(BIO_s_mem())` | Create in-memory buffer |
| `PEM_write_bio_PUBKEY(bio, pkey)` | Write PEM-encoded public key to buffer |
| `BIO_get_mem_data(bio, &ptr)` | Get pointer to buffer contents |
| `BIO_free(bio)` | Free the buffer |

**OpenSSL 3.0 note**: `RSA_new()`, `RSA_set0_key()`, `EC_KEY_*` are deprecated in OpenSSL 3.0 in favor of the `EVP_PKEY_fromdata()` API. We suppress the deprecation warnings with `#pragma GCC diagnostic` because the deprecated API still works, is clearer, and the new API is significantly more verbose. The functions aren't going away any time soon.

---

## Build System

### Makefile Walkthrough

```makefile
CFLAGS=-Wall -Wextra -fPIC -D_GNU_SOURCE
```

- `-Wall -Wextra` - Enable most compiler warnings
- `-fPIC` - Position-Independent Code, required for shared libraries (`.so`)
- `-D_GNU_SOURCE` - Enables `strndup()` and other GNU extensions

```makefile
OBJECTS=pam_oauth2.o oidc.o jwt_verify.o
LDLIBS=-ljwt -ljansson -lcurl -lssl -lcrypto
```

Make automatically compiles `.c` to `.o` using `$(CC) $(CFLAGS) -c`. Then we link all objects into a shared library:

```makefile
pam_oauth2.so: $(OBJECTS)
	$(CC) -shared $^ $(LDLIBS) -o $@
```

- `-shared` - Produce a shared library instead of an executable
- `$^` - All prerequisites (the .o files)
- `$@` - The target name (pam_oauth2.so)

### Platform Detection

The Makefile detects whether to install in `/lib/security/`, `/lib/x86_64-linux-gnu/security/` (Debian multiarch), or `/lib64/security/` (RedHat).

---

## Debugging

### Enable Debug Logging

Add `debug` to the PAM config line:

```
auth sufficient pam_oauth2.so https://login.example.com sub debug
```

### View Logs

```bash
# Follow auth logs in real-time
sudo journalctl -f -t pam_oauth2
# or
sudo tail -f /var/log/auth.log | grep pam_oauth2
```

### Debug Output Examples

**Successful authentication:**
```
pam_oauth2: authenticating user 'alice' against issuer 'https://login.example.com'
pam_oauth2: using cached JWKS (age: 3600 seconds, TTL: 1296000)
pam_oauth2: JWT header: alg=RS256 kid=abc123
pam_oauth2: JWKS contains 2 key(s)
pam_oauth2: converting RSA key to PEM
pam_oauth2: claim 'aud' matched
pam_oauth2: successfully authenticated 'alice'
```

**Cache miss with fresh fetch:**
```
pam_oauth2: JWKS cache missing, refreshing
pam_oauth2: fetching discovery document: https://login.example.com/.well-known/openid-configuration
pam_oauth2: fetching JWKS from https://login.example.com/.well-known/jwks
pam_oauth2: JWKS cached to /var/cache/pam_oauth2/a1b2c3d4...
```

**Expired token:**
```
pam_oauth2: token expired
```

### Inspect the Cache

```bash
# Find cache directory for an issuer
echo -n "https://login.example.com" | sha256sum
# a1b2c3d4...

# View cached keys
sudo cat /var/cache/pam_oauth2/a1b2c3d4.../jwks.json | python3 -m json.tool

# Check cache age
sudo cat /var/cache/pam_oauth2/a1b2c3d4.../metadata.json
# {"fetched_at": 1706000000}
date -d @1706000000
```

### Force Cache Refresh

```bash
# Delete cache to force re-fetch on next auth
sudo rm -rf /var/cache/pam_oauth2/

# Or set a very short TTL for testing
auth sufficient pam_oauth2.so https://login.example.com sub ttl=5 debug
```

---

## Testing

### Manual Test with pamtester

```bash
sudo apt-get install pamtester

# Create a test PAM config
sudo tee /etc/pam.d/test-oauth2 <<'EOF'
auth sufficient pam_oauth2.so https://login.example.com sub debug
auth required pam_deny.so
EOF

# Test (will prompt for password, paste a JWT token)
pamtester test-oauth2 alice authenticate
```

### Test with a Local RSA Key

```bash
# Generate a test RSA key pair
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem

# Extract n and e in base64url format (for building a test JWKS)
python3 -c "
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64, json

with open('public.pem', 'rb') as f:
    pub = load_pem_public_key(f.read())
nums = pub.public_numbers()

def b64url(n, length):
    return base64.urlsafe_b64encode(n.to_bytes(length, 'big')).rstrip(b'=').decode()

jwks = {'keys': [{'kty':'RSA', 'kid':'test-key', 'use':'sig', 'alg':'RS256',
         'n': b64url(nums.n, 256), 'e': b64url(nums.e, 3)}]}
print(json.dumps(jwks, indent=2))
"
# Place output in the cache directory as jwks.json

# Create a test JWT
python3 -c "
import jwt, time
token = jwt.encode(
    {'iss':'https://login.example.com', 'sub':'alice', 'exp':int(time.time())+3600, 'aud':'myapp'},
    open('private.pem').read(),
    algorithm='RS256',
    headers={'kid':'test-key'}
)
print(token)
"
# Use this token as the password in pamtester
```

### Test Discovery Against Real Providers

```bash
# Google's OIDC discovery
curl -s https://accounts.google.com/.well-known/openid-configuration | python3 -m json.tool

# Fetch Google's JWKS
curl -s https://www.googleapis.com/oauth2/v3/certs | python3 -m json.tool
```

---

## Common Pitfalls

### "PAM_AUTHINFO_UNAVAIL on every request"

- **No cache and network failure**: Check if the issuer URL is reachable from the server. Try `curl -v https://your-issuer/.well-known/openid-configuration`.
- **Cache directory permissions**: The module runs as root. Ensure `/var/cache/pam_oauth2/` is writable by root.
- **Not HTTPS**: The module rejects `http://` URLs. Your issuer must use HTTPS.

### "PAM_AUTH_ERR but the token looks valid"

- **Issuer mismatch**: The `iss` claim must *exactly* match the configured issuer URL (including trailing slash or lack thereof).
- **Token expired**: Check the `exp` claim. Decode the JWT at jwt.io to inspect it.
- **Wrong login_field**: If you configured `sub` but the token uses `email` for the username.
- **Clock skew**: If the server's clock is off, `exp` checks may fail unexpectedly.

### "Works with one provider but not another"

- **Key type**: We support RSA and EC keys. If the provider uses EdDSA (Ed25519), that's not yet supported.
- **Algorithm**: We only accept RS256/384/512 and ES256/384/512. Some providers may use PS256 (RSA-PSS).
- **Multiple keys with no kid**: If the JWT header has no `kid` and the JWKS has multiple keys, we reject. The provider should include `kid` in tokens.

### "Builds fail on CentOS/RHEL"

- libjwt may not be in the default repos. Install EPEL first: `yum install epel-release`.
- OpenSSL version: RHEL 7 ships OpenSSL 1.0.2 which doesn't have `RSA_set0_key()`. You need OpenSSL 1.1.0+ (RHEL 8+).

### "OpenSSL deprecation warnings"

The `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` in `jwt_verify.c` suppresses these. The deprecated RSA/EC APIs still work in OpenSSL 3.x and are significantly simpler than the replacement `EVP_PKEY_fromdata()` API.
