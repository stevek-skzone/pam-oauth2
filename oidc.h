#ifndef OIDC_H
#define OIDC_H

/*
 * Load JWKS from cache or fetch from issuer's OIDC discovery endpoint.
 * Returns allocated JWKS JSON string on success, NULL on failure.
 * Caller must free the returned string.
 */
char *load_jwks_if_needed(const char *issuer_url, int ttl_seconds, int debug);

#endif /* OIDC_H */
