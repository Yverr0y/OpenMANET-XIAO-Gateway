#include "auth.h"

#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/md.h"

#include "provisioning.h"

static const char *TAG = "auth";

#define AUTH_SESSION_MAX 4 /* a phone plus a laptop plus headroom, not an open-ended table */

/* Lockout schedule: locks at the 5th failure, doubling on each failure that
 * lands while *not* currently locked (i.e. across separate lockout windows -
 * a failure that arrives while already locked is rejected before it's ever
 * evaluated, so it can't itself grow the lockout), capped at 5 minutes. */
#define AUTH_LOCKOUT_THRESHOLD 5
#define AUTH_LOCKOUT_BASE_S    30
#define AUTH_LOCKOUT_MAX_S     300

#define AUTH_CHALLENGE_TTL_US  (30LL * 1000000LL)        /* one login round trip */
#define AUTH_SALT_OFFER_TTL_US (120LL * 1000000LL)       /* generous - a human is typing */
#define AUTH_SESSION_IDLE_US   (30LL * 60 * 1000000LL)   /* 30 minutes */

/* Stored per-credential in gw_auth_config_t.iterations rather than assumed
 * fixed, so this can be tuned later without stranding already-provisioned
 * devices - see gw_config.h's own comment. This is only the value handed out
 * for a *new* password; an existing credential's own stored iterations
 * count is what login actually verifies against. */
#define AUTH_PBKDF2_ITERATIONS 100000

typedef struct {
    bool in_use;
    char token_hex[AUTH_TOKEN_HEX_LEN + 1];
    int64_t last_seen_us;
} auth_session_t;

typedef struct {
    bool active;
    char nonce_hex[AUTH_NONCE_HEX_LEN + 1];
    int64_t issued_us;
} auth_pending_challenge_t;

typedef struct {
    bool active;
    uint8_t salt[16];
    uint32_t iterations;
    int64_t issued_us;
} auth_pending_salt_t;

static gw_config_t *s_cfg = NULL;

/* Guards everything below - the session table, both single-slot pending
 * offers, and the lockout counters. Deliberately separate from
 * provisioning.c's s_cfg_lock, which is config-(NVS blob)-only; this state
 * is RAM-only and unrelated to gw_config_t mutation. gw_config_t's own
 * .auth fields are still read/written under provisioning_config_lock() at
 * the points that touch them, same as every other field. */
static SemaphoreHandle_t s_auth_lock = NULL;

static auth_session_t s_sessions[AUTH_SESSION_MAX];
static auth_pending_challenge_t s_pending_challenge;
static auth_pending_salt_t s_pending_salt;

static uint8_t s_fail_count = 0;
static int64_t s_locked_until_us = 0;

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (hex == NULL || strlen(hex) != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Full-length, no early exit - this is the one comparison in this file that
 * actually guards a secret (the login HMAC); session-token lookups below use
 * plain strcmp(), which is proportionate for a bearer token already behind
 * HttpOnly + the existing subnet check, but not for a password-derived
 * value an attacker could otherwise learn one byte at a time via timing. */
static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Caller must hold s_auth_lock. Mints a fresh token into token_hex_out and
 * installs it, evicting the least-recently-seen slot if the table is full -
 * mirrors the lru_purge_enable idea main/web_ui.c already applies to httpd
 * sockets, applied here to sessions instead. */
static void session_create_locked(char *token_hex_out)
{
    uint8_t token_bytes[16];
    esp_fill_random(token_bytes, sizeof(token_bytes));
    bytes_to_hex(token_bytes, sizeof(token_bytes), token_hex_out);

    int slot = -1;
    int64_t oldest_seen = INT64_MAX;
    int oldest_idx = 0;
    for (int i = 0; i < AUTH_SESSION_MAX; i++) {
        if (!s_sessions[i].in_use) {
            slot = i;
            break;
        }
        if (s_sessions[i].last_seen_us < oldest_seen) {
            oldest_seen = s_sessions[i].last_seen_us;
            oldest_idx = i;
        }
    }
    if (slot < 0) {
        slot = oldest_idx;
    }

    s_sessions[slot].in_use = true;
    strlcpy(s_sessions[slot].token_hex, token_hex_out, sizeof(s_sessions[slot].token_hex));
    s_sessions[slot].last_seen_us = esp_timer_get_time();
}

esp_err_t auth_init(gw_config_t *cfg)
{
    if (cfg == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    s_cfg = cfg;

    s_auth_lock = xSemaphoreCreateMutex();
    if (s_auth_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool auth_password_is_set(void)
{
    provisioning_config_lock();
    bool set = s_cfg->auth.password_set;
    provisioning_config_unlock();
    return set;
}

bool auth_is_locked_out(uint32_t *retry_after_s_out)
{
    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    int64_t now = esp_timer_get_time();
    bool locked = s_locked_until_us > now;
    if (locked && retry_after_s_out != NULL) {
        *retry_after_s_out = (uint32_t)((s_locked_until_us - now + 999999) / 1000000);
    }
    xSemaphoreGive(s_auth_lock);
    return locked;
}

bool auth_begin_login_challenge(char *nonce_hex_out, char *salt_hex_out, uint32_t *iterations_out)
{
    if (!auth_password_is_set()) {
        return false;
    }

    uint8_t nonce_bytes[16];
    esp_fill_random(nonce_bytes, sizeof(nonce_bytes));
    bytes_to_hex(nonce_bytes, sizeof(nonce_bytes), nonce_hex_out);

    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    strlcpy(s_pending_challenge.nonce_hex, nonce_hex_out, sizeof(s_pending_challenge.nonce_hex));
    s_pending_challenge.active = true;
    s_pending_challenge.issued_us = esp_timer_get_time();
    xSemaphoreGive(s_auth_lock);

    provisioning_config_lock();
    bytes_to_hex(s_cfg->auth.salt, sizeof(s_cfg->auth.salt), salt_hex_out);
    *iterations_out = s_cfg->auth.iterations;
    provisioning_config_unlock();

    return true;
}

auth_login_result_t auth_verify_login(const char *nonce_hex, const char *response_hex,
                                       char *token_hex_out, uint32_t *retry_after_s_out)
{
    xSemaphoreTake(s_auth_lock, portMAX_DELAY);

    int64_t now = esp_timer_get_time();
    if (s_locked_until_us > now) {
        if (retry_after_s_out != NULL) {
            *retry_after_s_out = (uint32_t)((s_locked_until_us - now + 999999) / 1000000);
        }
        xSemaphoreGive(s_auth_lock);
        return AUTH_LOGIN_LOCKED_OUT;
    }

    /* Single-use regardless of outcome, cleared right here - a captured
     * (nonce, response) pair can never be replayed. */
    bool challenge_ok = s_pending_challenge.active &&
                         (now - s_pending_challenge.issued_us) < AUTH_CHALLENGE_TTL_US &&
                         nonce_hex != NULL &&
                         strcmp(s_pending_challenge.nonce_hex, nonce_hex) == 0;
    s_pending_challenge.active = false;

    if (!challenge_ok) {
        xSemaphoreGive(s_auth_lock);
        return AUTH_LOGIN_NO_CHALLENGE;
    }

    uint8_t nonce_bytes[16];
    uint8_t response_bytes[32];
    if (!hex_to_bytes(nonce_hex, nonce_bytes, sizeof(nonce_bytes)) ||
        !hex_to_bytes(response_hex, response_bytes, sizeof(response_bytes))) {
        xSemaphoreGive(s_auth_lock);
        return AUTH_LOGIN_NO_CHALLENGE; /* malformed request - same as no valid challenge */
    }

    provisioning_config_lock();
    uint8_t stored_key[32];
    memcpy(stored_key, s_cfg->auth.stored_key, sizeof(stored_key));
    provisioning_config_unlock();

    uint8_t expected[32];
    int rc = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                              stored_key, sizeof(stored_key),
                              nonce_bytes, sizeof(nonce_bytes),
                              expected);

    if (rc == 0 && constant_time_equal(expected, response_bytes, sizeof(expected))) {
        s_fail_count = 0;
        s_locked_until_us = 0;
        session_create_locked(token_hex_out);
        xSemaphoreGive(s_auth_lock);
        return AUTH_LOGIN_OK;
    }

    if (s_fail_count < UINT8_MAX) {
        s_fail_count++;
    }
    if (s_fail_count >= AUTH_LOCKOUT_THRESHOLD) {
        uint32_t duration_s = AUTH_LOCKOUT_BASE_S;
        uint32_t shift = s_fail_count - AUTH_LOCKOUT_THRESHOLD;
        for (uint32_t i = 0; i < shift && duration_s < AUTH_LOCKOUT_MAX_S; i++) {
            duration_s *= 2;
        }
        if (duration_s > AUTH_LOCKOUT_MAX_S) {
            duration_s = AUTH_LOCKOUT_MAX_S;
        }
        s_locked_until_us = now + (int64_t)duration_s * 1000000;
    }

    xSemaphoreGive(s_auth_lock);
    return AUTH_LOGIN_BAD_CREDENTIALS;
}

bool auth_check_session(const char *token_hex)
{
    if (token_hex == NULL) {
        return false;
    }

    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    int64_t now = esp_timer_get_time();
    bool ok = false;
    for (int i = 0; i < AUTH_SESSION_MAX; i++) {
        if (s_sessions[i].in_use && strcmp(s_sessions[i].token_hex, token_hex) == 0) {
            if (now - s_sessions[i].last_seen_us > AUTH_SESSION_IDLE_US) {
                s_sessions[i].in_use = false; /* idle timeout - drop it rather than extend it */
            } else {
                s_sessions[i].last_seen_us = now; /* sliding idle timeout */
                ok = true;
            }
            break;
        }
    }
    xSemaphoreGive(s_auth_lock);
    return ok;
}

void auth_end_session(const char *token_hex)
{
    if (token_hex == NULL) {
        return;
    }
    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    for (int i = 0; i < AUTH_SESSION_MAX; i++) {
        if (s_sessions[i].in_use && strcmp(s_sessions[i].token_hex, token_hex) == 0) {
            s_sessions[i].in_use = false;
            break;
        }
    }
    xSemaphoreGive(s_auth_lock);
}

void auth_begin_password_salt(char *salt_hex_out, uint32_t *iterations_out)
{
    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    esp_fill_random(s_pending_salt.salt, sizeof(s_pending_salt.salt));
    s_pending_salt.iterations = AUTH_PBKDF2_ITERATIONS;
    s_pending_salt.active = true;
    s_pending_salt.issued_us = esp_timer_get_time();
    bytes_to_hex(s_pending_salt.salt, sizeof(s_pending_salt.salt), salt_hex_out);
    *iterations_out = s_pending_salt.iterations;
    xSemaphoreGive(s_auth_lock);
}

auth_set_password_result_t auth_commit_password(const char *stored_key_hex, char *token_hex_out)
{
    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    int64_t now = esp_timer_get_time();
    bool salt_ok = s_pending_salt.active && (now - s_pending_salt.issued_us) < AUTH_SALT_OFFER_TTL_US;
    if (!salt_ok) {
        xSemaphoreGive(s_auth_lock);
        return AUTH_SET_NO_PENDING_SALT;
    }

    uint8_t stored_key[32];
    if (!hex_to_bytes(stored_key_hex, stored_key, sizeof(stored_key))) {
        xSemaphoreGive(s_auth_lock);
        return AUTH_SET_BAD_KEY;
    }

    /* Salt/iterations come from the offer this module generated, never from
     * the request - a client can't smuggle in a weaker pair. Single-use,
     * cleared here regardless of what happens next. */
    uint8_t salt_copy[16];
    memcpy(salt_copy, s_pending_salt.salt, sizeof(salt_copy));
    uint32_t iterations_copy = s_pending_salt.iterations;
    s_pending_salt.active = false;
    xSemaphoreGive(s_auth_lock);

    /* Scratch-copy-then-save-then-writeback, matching config_post_handler's
     * own discipline (main/web_ui.c): never mutate the live s_cfg unless
     * provisioning_save() actually persisted it, so RAM and NVS can't
     * silently diverge on a failed write. */
    gw_config_t work;
    provisioning_config_lock();
    memcpy(&work, s_cfg, sizeof(work));
    memcpy(work.auth.salt, salt_copy, sizeof(work.auth.salt));
    work.auth.iterations = iterations_copy;
    memcpy(work.auth.stored_key, stored_key, sizeof(work.auth.stored_key));
    work.auth.password_set = true;

    esp_err_t err = provisioning_save(&work);
    if (err == ESP_OK) {
        memcpy(s_cfg, &work, sizeof(*s_cfg));
    }
    provisioning_config_unlock();

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to persist new credential: %s", esp_err_to_name(err));
        return AUTH_SET_SAVE_FAILED;
    }

    auth_drop_all_sessions();

    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    s_fail_count = 0;
    s_locked_until_us = 0;
    session_create_locked(token_hex_out);
    xSemaphoreGive(s_auth_lock);

    return AUTH_SET_OK;
}

void auth_drop_all_sessions(void)
{
    xSemaphoreTake(s_auth_lock, portMAX_DELAY);
    memset(s_sessions, 0, sizeof(s_sessions));
    xSemaphoreGive(s_auth_lock);
}
