#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/evp.h>

#include "oidc.h"

#define CACHE_BASE_DIR "/var/cache/pam_oauth2"
#define CONNECT_TIMEOUT 30L
#define TOTAL_TIMEOUT   60L
#define SHA256_HEX_LEN  64

struct http_response {
    char *data;
    size_t len;
};

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct http_response *resp = userdata;
    size_t data_size = size * nmemb;
    char *new_data = realloc(resp->data, resp->len + data_size + 1);

    if (!new_data)
        return 0;

    resp->data = new_data;
    memcpy(resp->data + resp->len, ptr, data_size);
    resp->len += data_size;
    resp->data[resp->len] = '\0';
    return data_size;
}

static char *http_get(const char *url, int debug)
{
    CURL *curl;
    struct http_response resp = { NULL, 0 };
    CURLcode res;
    long http_code = 0;

    if (strncmp(url, "https://", 8) != 0) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: refusing non-HTTPS URL");
        return NULL;
    }

    curl = curl_easy_init();
    if (!curl) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: curl_easy_init failed");
        return NULL;
    }

    resp.data = malloc(1);
    if (!resp.data) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    resp.data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TOTAL_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "pam_oauth2/2.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) {
        if (debug)
            syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: HTTP GET failed: %s (code %ld)",
                   curl_easy_strerror(res), http_code);
        free(resp.data);
        return NULL;
    }

    return resp.data;
}

static int compute_cache_path(const char *issuer_url, char *path, size_t path_len)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    unsigned int i;
    char hex[SHA256_HEX_LEN + 1];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx)
        return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, issuer_url, strlen(issuer_url)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    for (i = 0; i < hash_len; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);

    snprintf(path, path_len, "%s/%s", CACHE_BASE_DIR, hex);
    return 0;
}

static time_t read_cache_metadata(const char *cache_dir)
{
    char path[512];
    json_error_t err;
    json_t *root, *fetched_at;
    time_t result = -1;

    snprintf(path, sizeof(path), "%s/metadata.json", cache_dir);

    root = json_load_file(path, 0, &err);
    if (!root)
        return -1;

    fetched_at = json_object_get(root, "fetched_at");
    if (json_is_integer(fetched_at))
        result = (time_t)json_integer_value(fetched_at);

    json_decref(root);
    return result;
}

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[512];
    char *p;

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    return (mkdir(tmp, mode) != 0 && errno != EEXIST) ? -1 : 0;
}

static int write_cache(const char *cache_dir, const char *jwks_json, int debug)
{
    char path[512];
    FILE *f;
    json_t *meta;

    if (mkdir_p(cache_dir, 0700) != 0) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to create cache directory");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/jwks.json", cache_dir);
    f = fopen(path, "w");
    if (!f) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to write jwks.json");
        return -1;
    }
    fchmod(fileno(f), 0600);
    fputs(jwks_json, f);
    fclose(f);

    snprintf(path, sizeof(path), "%s/metadata.json", cache_dir);
    meta = json_object();
    json_object_set_new(meta, "fetched_at", json_integer(time(NULL)));
    if (json_dump_file(meta, path, 0) != 0) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to write metadata.json");
        json_decref(meta);
        return -1;
    }
    chmod(path, 0600);
    json_decref(meta);

    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: JWKS cached to %s", cache_dir);

    return 0;
}

static char *discover_jwks_uri(const char *issuer_url, int debug)
{
    char url[1024];
    char *response;
    json_error_t err;
    json_t *root, *jwks_uri;
    char *result = NULL;
    size_t len = strlen(issuer_url);

    if (len > 0 && issuer_url[len - 1] == '/')
        snprintf(url, sizeof(url), "%s.well-known/openid-configuration", issuer_url);
    else
        snprintf(url, sizeof(url), "%s/.well-known/openid-configuration", issuer_url);

    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: fetching discovery document: %s", url);

    response = http_get(url, debug);
    if (!response)
        return NULL;

    root = json_loads(response, 0, &err);
    free(response);
    if (!root) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to parse discovery document");
        return NULL;
    }

    jwks_uri = json_object_get(root, "jwks_uri");
    if (json_is_string(jwks_uri))
        result = strdup(json_string_value(jwks_uri));
    else
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: jwks_uri not found in discovery document");

    json_decref(root);
    return result;
}

static char *read_file_contents(const char *path)
{
    FILE *f;
    long len;
    char *buf;
    size_t read_len;

    f = fopen(path, "r");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0) {
        fclose(f);
        return NULL;
    }

    buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    read_len = fread(buf, 1, len, f);
    fclose(f);
    buf[read_len] = '\0';
    return buf;
}

char *load_jwks_if_needed(const char *issuer_url, int ttl_seconds, int debug)
{
    char cache_dir[512];
    char jwks_path[530];
    time_t fetched_at, now;
    int cache_valid;
    char *jwks_uri, *jwks_json;
    json_error_t err;
    json_t *root;

    if (compute_cache_path(issuer_url, cache_dir, sizeof(cache_dir)) != 0) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: failed to compute cache path");
        return NULL;
    }

    snprintf(jwks_path, sizeof(jwks_path), "%s/jwks.json", cache_dir);

    fetched_at = read_cache_metadata(cache_dir);
    now = time(NULL);
    cache_valid = (fetched_at > 0 && (now - fetched_at) <= ttl_seconds);

    if (cache_valid) {
        if (debug)
            syslog(LOG_AUTH|LOG_DEBUG,
                   "pam_oauth2: using cached JWKS (age: %ld seconds, TTL: %d)",
                   (long)(now - fetched_at), ttl_seconds);
        return read_file_contents(jwks_path);
    }

    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: JWKS cache %s, refreshing",
               fetched_at > 0 ? "expired" : "missing");

    jwks_uri = discover_jwks_uri(issuer_url, debug);
    if (!jwks_uri)
        goto stale_fallback;

    if (debug)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: fetching JWKS from %s", jwks_uri);

    jwks_json = http_get(jwks_uri, debug);
    free(jwks_uri);
    if (!jwks_json)
        goto stale_fallback;

    root = json_loads(jwks_json, 0, &err);
    if (!root || !json_is_array(json_object_get(root, "keys"))) {
        syslog(LOG_AUTH|LOG_ERR, "pam_oauth2: invalid JWKS response");
        if (root)
            json_decref(root);
        free(jwks_json);
        goto stale_fallback;
    }
    json_decref(root);

    write_cache(cache_dir, jwks_json, debug);
    return jwks_json;

stale_fallback:
    if (fetched_at > 0) {
        syslog(LOG_AUTH|LOG_NOTICE,
               "pam_oauth2: using stale JWKS cache (fetch failed)");
        return read_file_contents(jwks_path);
    }
    syslog(LOG_AUTH|LOG_ERR,
           "pam_oauth2: no JWKS available (fetch failed, no cache)");
    return NULL;
}
