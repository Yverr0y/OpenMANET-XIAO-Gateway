#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 30s x 240 samples = 2 hours of retention. A live-dashboard/field-test
 * window, not an overnight-unattended one - the log ring (log_buffer.h) and
 * chip_temp.h already cover "did it survive the night", this is for "how did
 * the link look during the walk test I was just running". */
#define LINK_HISTORY_SAMPLES    240
#define LINK_HISTORY_INTERVAL_S 30

/* Starts an esp_timer that samples the active uplink's RSSI (whichever of
 * uplink_halow_get_rssi()/uplink_wifi_get_rssi() isn't reporting its own
 * "not ready" sentinel - see link_history.c) into a ring buffer every
 * LINK_HISTORY_INTERVAL_S seconds. Safe to call once at boot regardless of
 * role. Takes one sample immediately so a page load right after boot isn't
 * empty. */
esp_err_t link_history_init(void);

/* Copies up to out_capacity samples into out, oldest first, and returns how
 * many were written. Each value is a signed RSSI in dBm, or INT16_MIN for
 * "no reading at that sample time" (radio not up yet, or link_history_init()
 * was never called/failed). */
size_t link_history_get_rssi(int16_t *out, size_t out_capacity);

#ifdef __cplusplus
}
#endif
