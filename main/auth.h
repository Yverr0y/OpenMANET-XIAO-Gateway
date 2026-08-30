#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#include "gw_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Web UI authentication (design/ROADMAP.md item 1): PBKDF2-HMAC-SHA256
 * credential verification, RAM-only sessions, and login lockout/backoff.
 *
 * Deliberately owns zero dependency on esp_http_server.h - main/web_ui.c
 * does all cookie/header/JSON plumbing and calls into the pure functions
 * below, the same split chip_temp.c/link_history.c already use to stay
 * independent of the HTTP layer.
 *
 * The PBKDF2 derivation itself never runs on this device. The client always
 * has the plaintext password (a human just typed it) and is the only party
 * that ever needs to *derive* a key from it; this module only ever *stores*
 * a already-derived stored_key (via auth_commit_password()) and *verifies*
 * a login attempt against it with one HMAC-SHA256 call. This keeps a
 * 100,000-round KDF loop off the already-tight GW_STACK_WEB_UI budget - see
 * main/CMakeLists.txt's mbedtls comment. */

/* Hex-encoded lengths (2 chars per byte) of the values this API exchanges. */
#define AUTH_SALT_HEX_LEN       32 /* 16 bytes */
#define AUTH_NONCE_HEX_LEN      32 /* 16 bytes */
#define AUTH_STORED_KEY_HEX_LEN 64 /* 32 bytes */
#define AUTH_RESPONSE_HEX_LEN   64 /* 32 bytes, same size as stored_key - both are HMAC-SHA256 output */
#define AUTH_TOKEN_HEX_LEN      32 /* 16 bytes */

/* Call once at boot (app_main.c, alongside provisioning_init()) - not from
 * inside web_ui_start(), because provisioning.c's gwcfg-reset-auth console
 * command (a sibling module) needs auth_drop_all_sessions() too. Stashes cfg
 * (already loaded by provisioning_load()) and creates the session/lockout
 * lock. */
esp_err_t auth_init(gw_config_t *cfg);

bool auth_password_is_set(void);

/* Fills nonce_hex_out (AUTH_NONCE_HEX_LEN+1 bytes), salt_hex_out
 * (AUTH_SALT_HEX_LEN+1 bytes) and *iterations_out from the currently stored
 * credential, and remembers the nonce as the single pending login challenge
 * (TTL 30s, single-use). Returns false without touching any output if no
 * password is set yet. */
bool auth_begin_login_challenge(char *nonce_hex_out, char *salt_hex_out, uint32_t *iterations_out);

typedef enum {
    AUTH_LOGIN_OK,
    AUTH_LOGIN_BAD_CREDENTIALS,
    AUTH_LOGIN_LOCKED_OUT,
    AUTH_LOGIN_NO_CHALLENGE,
} auth_login_result_t;

/* Verifies response_hex against the pending challenge issued by
 * auth_begin_login_challenge() for the given nonce_hex - the challenge is
 * consumed (cleared) by this call regardless of outcome, so a captured
 * response can never be replayed. On AUTH_LOGIN_OK, fills token_hex_out
 * (AUTH_TOKEN_HEX_LEN+1 bytes) with a freshly minted session token. On
 * AUTH_LOGIN_LOCKED_OUT, fills *retry_after_s_out. */
auth_login_result_t auth_verify_login(const char *nonce_hex, const char *response_hex,
                                       char *token_hex_out, uint32_t *retry_after_s_out);

/* True if the challenge slot is currently locked out (used so
 * auth_begin_login_challenge()'s caller can skip issuing a challenge - and
 * the client an expensive PBKDF2 derivation it can't use yet - while locked).
 * Fills *retry_after_s_out when returning true. */
bool auth_is_locked_out(uint32_t *retry_after_s_out);

/* Touches the session's last-seen time on a hit (sliding idle timeout). */
bool auth_check_session(const char *token_hex);

void auth_end_session(const char *token_hex);

/* Generates a fresh server-side salt for a password set/change, remembers it
 * as the single pending "salt offer" (TTL 120s), and fills salt_hex_out
 * (AUTH_SALT_HEX_LEN+1 bytes) and *iterations_out. */
void auth_begin_password_salt(char *salt_hex_out, uint32_t *iterations_out);

typedef enum {
    AUTH_SET_OK,
    AUTH_SET_NO_PENDING_SALT,
    AUTH_SET_BAD_KEY,
    AUTH_SET_SAVE_FAILED, /* provisioning_save() failed - live config is untouched, matching
                           * config_post_handler's own "don't write back unless persisted"
                           * discipline (main/web_ui.c) - the caller should surface a 500 */
} auth_set_password_result_t;

/* Commits stored_key_hex (must be exactly AUTH_STORED_KEY_HEX_LEN hex chars)
 * against the pending salt offer from auth_begin_password_salt() - the
 * salt/iterations actually written come from that offer, never from the
 * caller, so a client can't smuggle in a weaker pair. Persists immediately
 * via provisioning_save(); the live config is only updated if that succeeds.
 * On AUTH_SET_OK, drops every existing session (including the caller's) and
 * fills token_hex_out with a fresh one, so a password change never logs the
 * caller out. */
auth_set_password_result_t auth_commit_password(const char *stored_key_hex, char *token_hex_out);

/* Drops every live session immediately, without a reboot. Used by
 * gwcfg-reset-auth and internally by auth_commit_password(). */
void auth_drop_all_sessions(void);

#ifdef __cplusplus
}
#endif
