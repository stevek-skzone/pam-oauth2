#ifndef JWT_VERIFY_H
#define JWT_VERIFY_H

struct claim_check {
    const char *key;
    const char *value;
};

/*
 * Verify JWT token signature and validate all claims.
 * Returns PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN, or PAM_AUTHINFO_UNAVAIL.
 */
int verify_and_check_claims(const char *token, const char *jwks_json,
                            const char *issuer_url, const char *login_field,
                            const char *username, const struct claim_check *claims,
                            int num_claims, int debug);

#endif /* JWT_VERIFY_H */
