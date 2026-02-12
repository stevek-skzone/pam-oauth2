#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>

#include <jwt.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <security/pam_modules.h>

#include "jwt_verify.h"

/* Suppress OpenSSL 3.0 deprecation warnings for RSA/EC low-level API */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static unsigned char *base64url_decode(const char *input, int *out_len)
{
    int len = strlen(input);
    int pad = (4 - (len % 4)) % 4;
    int i, decoded_max;
    char *b64;
    unsigned char *decoded;

    b64 = malloc(len + pad + 1);
    if (!b64)
        return NULL;

    for (i = 0; i < len; i++) {
        if (input[i] == '-')
            b64[i] = '+';
        else if (input[i] == '_')
            b64[i] = '/';
        else
            b64[i] = input[i];
    }
    for (i = 0; i < pad; i++)
        b64[len + i] = '=';
    b64[len + pad] = '\0';

    decoded_max = ((len + pad) / 4) * 3;
    decoded = malloc(decoded_max + 1);
    if (!decoded) {
        free(b64);
        return NULL;
    }

    *out_len = EVP_DecodeBlock(decoded, (unsigned char *)b64, len + pad);
    free(b64);

    if (*out_len < 0) {
        free(decoded);
        return NULL;
    }

    /* EVP_DecodeBlock over-reports length by padding byte count */
    *out_len -= pad;
    return decoded;
}

static int parse_jwt_header(const char *token, char **kid, char **alg)
{
    const char *dot;
    int header_b64_len, decoded_len;
    char *header_b64;
    unsigned char *header_json;
    json_error_t err;
    json_t *root, *alg_val, *kid_val;

    *kid = NULL;
    *alg = NULL;

    dot = strchr(token, '.');
    if (!dot)
        return -1;

    header_b64_len = dot - token;
    header_b64 = strndup(token, header_b64_len);
    if (!header_b64)
        return -1;

    header_json = base64url_decode(header_b64, &decoded_len);
    free(header_b64);
    if (!header_json)
        return -1;

    header_json[decoded_len] = '\0';

    root = json_loads((char *)header_json, 0, &err);
    free(header_json);
    if (!root)
        return -1;

    alg_val = json_object_get(root, "alg");
    if (json_is_string(alg_val))
        *alg = strdup(json_string_value(alg_val));

    kid_val = json_object_get(root, "kid");
    if (json_is_string(kid_val))
        *kid = strdup(json_string_value(kid_val));

    json_decref(root);
    return (*alg != NULL) ? 0 : -1;
}

static int is_allowed_algorithm(const char *alg)
{
    return (strcmp(alg, "RS256") == 0 || strcmp(alg, "RS384") == 0 ||
            strcmp(alg, "RS512") == 0 || strcmp(alg, "ES256") == 0 ||
            strcmp(alg, "ES384") == 0 || strcmp(alg, "ES512") == 0);
}

static json_t *find_key_in_jwks(const char *jwks_json, const char *kid, int debug)
{
    json_error_t err;
    json_t *root, *keys, *matched = NULL;
    size_t key_count, i;

    root = json_loads(jwks_json, 0, &err);
    if (!root) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to parse JWKS");
        return NULL;
    }

    keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: JWKS missing 'keys' array");
        json_decref(root);
        return NULL;
    }

    key_count = json_array_size(keys);
    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: JWKS contains %zu key(s)", key_count);

    if (kid) {
        for (i = 0; i < key_count; i++) {
            json_t *key = json_array_get(keys, i);
            json_t *key_kid = json_object_get(key, "kid");
            if (json_is_string(key_kid) &&
                strcmp(json_string_value(key_kid), kid) == 0) {
                matched = json_deep_copy(key);
                break;
            }
        }
        if (!matched && debug)
            syslog(LOG_AUTH|LOG_DEBUG,
                   "pam_oauth2: no key found matching kid '%s'", kid);
    } else if (key_count == 1) {
        matched = json_deep_copy(json_array_get(keys, 0));
        if (debug)
            syslog(LOG_AUTH|LOG_DEBUG,
                   "pam_oauth2: no kid in header, using single JWKS key");
    } else {
        syslog(LOG_AUTH|LOG_ERR,
               "pam_oauth2: no kid in header and JWKS has %zu keys", key_count);
    }

    json_decref(root);
    return matched;
}

static char *rsa_jwk_to_pem(json_t *key)
{
    char *pem = NULL;
    unsigned char *n_bin = NULL, *e_bin = NULL;
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    const char *n_b64, *e_b64;
    int n_len, e_len;

    n_b64 = json_string_value(json_object_get(key, "n"));
    e_b64 = json_string_value(json_object_get(key, "e"));
    if (!n_b64 || !e_b64)
        return NULL;

    n_bin = base64url_decode(n_b64, &n_len);
    e_bin = base64url_decode(e_b64, &e_len);
    if (!n_bin || !e_bin)
        goto cleanup;

    n_bn = BN_bin2bn(n_bin, n_len, NULL);
    e_bn = BN_bin2bn(e_bin, e_len, NULL);
    if (!n_bn || !e_bn)
        goto cleanup;

    rsa = RSA_new();
    if (!rsa)
        goto cleanup;

    if (RSA_set0_key(rsa, n_bn, e_bn, NULL) != 1)
        goto cleanup;
    /* Ownership transferred to RSA */
    n_bn = NULL;
    e_bn = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey)
        goto cleanup;

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
        goto cleanup;
    /* Ownership transferred to EVP_PKEY */
    rsa = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
        goto cleanup;

    if (PEM_write_bio_PUBKEY(bio, pkey) == 1) {
        char *pem_data;
        long pem_len = BIO_get_mem_data(bio, &pem_data);
        pem = strndup(pem_data, pem_len);
    }

cleanup:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(n_bn);
    BN_free(e_bn);
    free(n_bin);
    free(e_bin);
    return pem;
}

static int curve_name_to_nid(const char *crv)
{
    if (strcmp(crv, "P-256") == 0) return NID_X9_62_prime256v1;
    if (strcmp(crv, "P-384") == 0) return NID_secp384r1;
    if (strcmp(crv, "P-521") == 0) return NID_secp521r1;
    return 0;
}

static char *ec_jwk_to_pem(json_t *key)
{
    char *pem = NULL;
    unsigned char *x_bin = NULL, *y_bin = NULL;
    BIGNUM *x_bn = NULL, *y_bn = NULL;
    EC_KEY *ec = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    const char *crv, *x_b64, *y_b64;
    int nid, x_len, y_len;

    crv = json_string_value(json_object_get(key, "crv"));
    x_b64 = json_string_value(json_object_get(key, "x"));
    y_b64 = json_string_value(json_object_get(key, "y"));
    if (!crv || !x_b64 || !y_b64)
        return NULL;

    nid = curve_name_to_nid(crv);
    if (nid == 0)
        return NULL;

    x_bin = base64url_decode(x_b64, &x_len);
    y_bin = base64url_decode(y_b64, &y_len);
    if (!x_bin || !y_bin)
        goto cleanup;

    x_bn = BN_bin2bn(x_bin, x_len, NULL);
    y_bn = BN_bin2bn(y_bin, y_len, NULL);
    if (!x_bn || !y_bn)
        goto cleanup;

    ec = EC_KEY_new_by_curve_name(nid);
    if (!ec)
        goto cleanup;

    if (EC_KEY_set_public_key_affine_coordinates(ec, x_bn, y_bn) != 1)
        goto cleanup;

    pkey = EVP_PKEY_new();
    if (!pkey)
        goto cleanup;

    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1)
        goto cleanup;
    /* Ownership transferred to EVP_PKEY */
    ec = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
        goto cleanup;

    if (PEM_write_bio_PUBKEY(bio, pkey) == 1) {
        char *pem_data;
        long pem_len = BIO_get_mem_data(bio, &pem_data);
        pem = strndup(pem_data, pem_len);
    }

cleanup:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec);
    BN_free(x_bn);
    BN_free(y_bn);
    free(x_bin);
    free(y_bin);
    return pem;
}

static char *jwks_key_to_pem(json_t *key, int debug)
{
    const char *kty = json_string_value(json_object_get(key, "kty"));

    if (!kty) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: JWKS key missing 'kty'");
        return NULL;
    }

    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: converting %s key to PEM", kty);

    if (strcmp(kty, "RSA") == 0)
        return rsa_jwk_to_pem(key);
    if (strcmp(kty, "EC") == 0)
        return ec_jwk_to_pem(key);

    syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: unsupported key type '%s'", kty);
    return NULL;
}

static int validate_claims(jwt_t *jwt, const char *issuer_url,
                           const char *login_field, const char *username,
                           const struct claim_check *claims, int num_claims,
                           int debug)
{
    const char *iss, *login_value, *value;
    long exp_val;
    int i;

    /* Check issuer */
    iss = jwt_get_grant(jwt, "iss");
    if (!iss || strcmp(iss, issuer_url) != 0) {
        syslog(LOG_AUTH|LOG_NOTICE, "pam_oauth2: issuer mismatch");
        return PAM_AUTH_ERR;
    }

    /* Check expiration */
    errno = 0;
    exp_val = jwt_get_grant_int(jwt, "exp");
    if (errno == ENOENT) {
        syslog(LOG_AUTH|LOG_NOTICE, "pam_oauth2: token missing 'exp' claim");
        return PAM_AUTH_ERR;
    }
    if (exp_val <= (long)time(NULL)) {
        syslog(LOG_AUTH|LOG_NOTICE, "pam_oauth2: token expired");
        return PAM_AUTH_ERR;
    }

    /* Check login field matches username */
    login_value = jwt_get_grant(jwt, login_field);
    if (!login_value) {
        if (debug)
            syslog(LOG_AUTH|LOG_DEBUG,
                   "pam_oauth2: claim '%s' not found in token", login_field);
        return PAM_USER_UNKNOWN;
    }
    if (strcmp(login_value, username) != 0) {
        if (debug)
            syslog(LOG_AUTH|LOG_DEBUG,
                   "pam_oauth2: claim '%s' value doesn't match username",
                   login_field);
        return PAM_AUTH_ERR;
    }

    /* Check additional claims */
    for (i = 0; i < num_claims; i++) {
        value = jwt_get_grant(jwt, claims[i].key);
        if (!value || strcmp(value, claims[i].value) != 0) {
            syslog(LOG_AUTH|LOG_NOTICE,
                   "pam_oauth2: claim '%s' mismatch", claims[i].key);
            if (debug && value)
                syslog(LOG_AUTH|LOG_DEBUG,
                       "pam_oauth2: expected '%s'='%s', got '%s'",
                       claims[i].key, claims[i].value, value);
            return PAM_AUTH_ERR;
        }
        if (debug)
            syslog(LOG_AUTH|LOG_DEBUG,
                   "pam_oauth2: claim '%s' matched", claims[i].key);
    }

    return PAM_SUCCESS;
}

int verify_and_check_claims(const char *token, const char *jwks_json,
                            const char *issuer_url, const char *login_field,
                            const char *username, const struct claim_check *claims,
                            int num_claims, int debug)
{
    int result = PAM_AUTH_ERR;
    char *kid = NULL, *alg = NULL, *pem = NULL;
    json_t *jwk = NULL;
    jwt_t *jwt = NULL;
    jwt_alg_t jwt_alg;
    int rc;

    /* Parse JWT header */
    if (parse_jwt_header(token, &kid, &alg) != 0) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to parse JWT header");
        goto cleanup;
    }

    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: JWT header: alg=%s kid=%s",
               alg ? alg : "(none)", kid ? kid : "(none)");

    /* Validate algorithm */
    if (!is_allowed_algorithm(alg)) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: rejected algorithm '%s'", alg);
        goto cleanup;
    }

    /* Find key in JWKS */
    jwk = find_key_in_jwks(jwks_json, kid, debug);
    if (!jwk) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: no matching key found in JWKS");
        goto cleanup;
    }

    /* Convert JWKS key to PEM */
    pem = jwks_key_to_pem(jwk, debug);
    if (!pem) {
        syslog(LOG_AUTH|LOG_ERR,
               "pam_oauth2: failed to convert JWKS key to PEM");
        goto cleanup;
    }

    /* Verify JWT signature */
    rc = jwt_decode(&jwt, token, (unsigned char *)pem, (int)strlen(pem));
    if (rc != 0) {
        syslog(LOG_AUTH|LOG_NOTICE,
               "pam_oauth2: JWT signature verification failed");
        goto cleanup;
    }

    /* Double-check algorithm after decode (defense in depth) */
    jwt_alg = jwt_get_alg(jwt);
    if (jwt_alg == JWT_ALG_NONE || jwt_alg == JWT_ALG_HS256 ||
        jwt_alg == JWT_ALG_HS384 || jwt_alg == JWT_ALG_HS512) {
        syslog(LOG_AUTH|LOG_ERR,
               "pam_oauth2: rejected algorithm after decode");
        goto cleanup;
    }

    /* Validate claims */
    result = validate_claims(jwt, issuer_url, login_field, username,
                             claims, num_claims, debug);

cleanup:
    free(kid);
    free(alg);
    free(pem);
    if (jwk)
        json_decref(jwk);
    if (jwt)
        jwt_free(jwt);
    return result;
}

#pragma GCC diagnostic pop
