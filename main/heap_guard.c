#include "heap_guard.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

static const char *TAG = "heap_guard";

#define SAMPLE_INTERVAL_S 5

static esp_netif_t *s_softap_netif = NULL;
static esp_timer_handle_t s_timer = NULL;
static bool s_dhcp_paused = false;

/* Read by cot_relay.c's relay_task, written only from sample_timer_cb() below
 * (the esp_timer service task - esp_timer.h's own docs on the default
 * ESP_TIMER_TASK dispatch method). A torn read of a single bool isn't
 * possible on this target, and a stale read for up to one SAMPLE_INTERVAL_S
 * is harmless - same tolerance cot_relay.c's own rx counters already rely on
 * (see that file's relay_task comment) - so this is deliberately not behind
 * a lock. */
static bool s_shed_cot = false;

/* Pauses/resumes the SoftAP's DHCP server as free *internal* heap crosses
 * GW_HEAP_NODE_SHED_BYTES - see that macro's doc comment in heap_guard.h for
 * why internal SRAM, not the PSRAM-inflated combined figure, is what this
 * checks. No-op on a GW_ROLE_RELAY node (s_softap_netif is NULL there). */
static void apply_node_shed(uint32_t free_internal_bytes)
{
    if (s_softap_netif == NULL) {
        return;
    }

    bool should_pause = free_internal_bytes < GW_HEAP_NODE_SHED_BYTES;
    if (should_pause == s_dhcp_paused) {
        return;
    }

    esp_err_t err = should_pause ? esp_netif_dhcps_stop(s_softap_netif)
                                  : esp_netif_dhcps_start(s_softap_netif);
    /* Racing whatever else touches this netif's DHCP server (e.g.
     * downlink_softap.c at init) just means one of the two calls sees
     * "already stopped/started" - harmless, not worth escalating past a
     * warning. */
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED &&
        err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
        ESP_LOGW(TAG, "dhcps_%s failed: %s", should_pause ? "stop" : "start", esp_err_to_name(err));
        return;
    }

    s_dhcp_paused = should_pause;
    if (should_pause) {
        ESP_LOGW(TAG, "free internal heap %u bytes < %u - pausing new SoftAP associations",
                 (unsigned)free_internal_bytes, (unsigned)GW_HEAP_NODE_SHED_BYTES);
    } else {
        ESP_LOGI(TAG, "free internal heap %u bytes - resuming new SoftAP associations",
                 (unsigned)free_internal_bytes);
    }
}

static void sample_timer_cb(void *arg)
{
    (void)arg;
    /* Internal SRAM, not esp_get_free_heap_size() - see
     * GW_HEAP_COT_SHED_BYTES's doc comment in heap_guard.h for why the
     * PSRAM-inflated combined figure is the wrong thing to react to here. */
    uint32_t free_internal_bytes = esp_get_free_internal_heap_size();

    bool should_shed = free_internal_bytes < GW_HEAP_COT_SHED_BYTES;
    if (should_shed != s_shed_cot) {
        ESP_LOGW(TAG, "CoT relay shed %s (free internal heap %u bytes, threshold %u)",
                 should_shed ? "engaged" : "cleared", (unsigned)free_internal_bytes,
                 (unsigned)GW_HEAP_COT_SHED_BYTES);
    }
    s_shed_cot = should_shed;

    apply_node_shed(free_internal_bytes);
}

esp_err_t heap_guard_init(esp_netif_t *softap_netif)
{
    s_softap_netif = softap_netif;

    /* Default dispatch method is ESP_TIMER_TASK (esp_timer.h), so
     * sample_timer_cb()'s esp_netif_dhcps_*() calls below - not ISR-safe -
     * are fine here. Same pattern as link_history.c's own timer. */
    const esp_timer_create_args_t timer_args = {
        .callback = sample_timer_cb,
        .name = "heap_guard",
    };
    esp_err_t err = esp_timer_create(&timer_args, &s_timer);
    if (err != ESP_OK) {
        return err;
    }

    sample_timer_cb(NULL); /* first reading exists immediately, not after SAMPLE_INTERVAL_S */

    err = esp_timer_start_periodic(s_timer, (uint64_t)SAMPLE_INTERVAL_S * 1000000ULL);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_timer_start_periodic failed: %s", esp_err_to_name(err));
    }
    return err;
}

bool heap_guard_should_shed_cot(void)
{
    return s_shed_cot;
}

void heap_guard_get_stats(uint32_t *out_free_bytes, uint32_t *out_min_free_bytes,
                           uint32_t *out_free_internal_bytes)
{
    if (out_free_bytes != NULL) {
        *out_free_bytes = esp_get_free_heap_size();
    }
    if (out_min_free_bytes != NULL) {
        *out_min_free_bytes = esp_get_minimum_free_heap_size();
    }
    if (out_free_internal_bytes != NULL) {
        *out_free_internal_bytes = esp_get_free_internal_heap_size();
    }
}
