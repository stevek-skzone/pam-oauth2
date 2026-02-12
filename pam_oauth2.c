#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "oidc.h"
#include "jwt_verify.h"

#define DEFAULT_TTL 1296000  /* 15 days in seconds */

struct pam_oauth2_config {
    const char *issuer_url;
    const char *login_field;
    struct claim_check *claims;
    int num_claims;
    int ttl_seconds;
    int debug;
};

static void parse_config(int argc, const char **argv,
                          struct pam_oauth2_config *config)
{
    int i, claim_count = 0;

    config->issuer_url = NULL;
    config->login_field = NULL;
    config->claims = NULL;
    config->num_claims = 0;
    config->ttl_seconds = DEFAULT_TTL;
    config->debug = 0;

    if (argc > 0)
        config->issuer_url = argv[0];
    if (argc > 1)
        config->login_field = argv[1];

    /* Count claim=value pairs */
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0)
            continue;
        if (strncmp(argv[i], "ttl=", 4) == 0)
            continue;
        if (strchr(argv[i], '='))
            claim_count++;
    }

    if (claim_count > 0)
        config->claims = calloc(claim_count, sizeof(struct claim_check));

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            config->debug = 1;
        } else if (strncmp(argv[i], "ttl=", 4) == 0) {
            config->ttl_seconds = atoi(argv[i] + 4);
            if (config->ttl_seconds <= 0)
                config->ttl_seconds = DEFAULT_TTL;
        } else {
            const char *eq = strchr(argv[i], '=');
            if (eq && config->claims) {
                config->claims[config->num_claims].key =
                    strndup(argv[i], eq - argv[i]);
                config->claims[config->num_claims].value = eq + 1;
                config->num_claims++;
            }
        }
    }
}

static void free_config(struct pam_oauth2_config *config)
{
    int i;

    for (i = 0; i < config->num_claims; i++)
        free((char *)config->claims[i].key);
    free(config->claims);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    struct pam_oauth2_config config;
    const char *username = NULL, *authtok = NULL;
    char *jwks_json = NULL;
    int result;

    (void)flags;

    parse_config(argc, argv, &config);

    if (!config.issuer_url || !*config.issuer_url) {
        syslog(LOG_AUTH|LOG_ERR,
               "pam_oauth2: issuer_url is not defined or invalid");
        result = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    if (!config.login_field || !*config.login_field) {
        syslog(LOG_AUTH|LOG_ERR,
               "pam_oauth2: login_field is not defined or empty");
        result = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        !username || !*username) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: can't get user login");
        result = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS ||
        !authtok || !*authtok) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: can't get authtok");
        result = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    if (config.debug)
        syslog(LOG_AUTH|LOG_DEBUG,
               "pam_oauth2: authenticating user '%s' against issuer '%s'",
               username, config.issuer_url);

    jwks_json = load_jwks_if_needed(config.issuer_url, config.ttl_seconds,
                                     config.debug);
    if (!jwks_json) {
        result = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    result = verify_and_check_claims(authtok, jwks_json, config.issuer_url,
                                      config.login_field, username,
                                      config.claims, config.num_claims,
                                      config.debug);

    if (result == PAM_SUCCESS)
        syslog(LOG_AUTH|LOG_NOTICE,
               "pam_oauth2: successfully authenticated '%s'", username);

cleanup:
    free(jwks_json);
    free_config(&config);
    return result;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_CRED_UNAVAIL;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
