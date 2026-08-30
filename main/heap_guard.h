#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

/* Below this much free *internal* SRAM - esp_get_free_internal_heap_size(),
 * i.e. heap_caps_get_free_size(MALLOC_CAP_8BIT|MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL)
 * (esp-idf v5.5.1 components/esp_system/port/esp_system_chip.c) - the CoT
 * relay drops inbound datagrams instead of forwarding them: see
 * heap_guard_should_shed_cot().
 *
 * Deliberately *not* keyed off esp_get_free_heap_size() (the combined
 * internal+PSRAM figure MALLOC_CAP_DEFAULT reports once
 * CONFIG_SPIRAM_USE_MALLOC=y is on - sdkconfig.defaults' PSRAM block): with
 * an 8MB PSRAM pool behind it, that number stays huge right up until PSRAM
 * itself is nearly exhausted, which this workload is never expected to
 * reach. Internal SRAM is the resource that actually runs out first - pbufs
 * under CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL's 16KB default prefer it before
 * ever touching PSRAM, and DMA descriptors/task stacks can *only* live
 * there, PSRAM or not - so it's the one worth reacting to. A combined-heap
 * threshold would silently never fire while internal SRAM alone was already
 * in real trouble.
 *
 * CoT is UDP/best-effort and, by design, the highest-volume consumer of
 * lwIP's shared pbuf pool (main/cot_relay.h's cot_relay_counters_t comment);
 * shedding it first protects the low-volume, human-facing web UI/auth TCP
 * traffic the SoftAP's other clients depend on.
 *
 * No real-hardware measurement backs this number yet - internal SRAM is
 * ~512KB total on the S3, minus whatever the WiFi/HaLow drivers' own static
 * buffers, task stacks and this firmware's own state take before any of it
 * is "free" to begin with, and that baseline has never been read off a
 * running node. Placeholder pending a real /api/status heap_free_internal
 * reading - see design/ROADMAP.md. */
#define GW_HEAP_COT_SHED_BYTES  (64u * 1024u)

/* Below this much free internal SRAM - lower than GW_HEAP_COT_SHED_BYTES, so
 * this trips second, once shedding CoT alone hasn't been enough - the
 * SoftAP's DHCP server is paused so no *new* phone can associate and get an
 * address on an already-degraded node. Already-leased clients are untouched;
 * this only refuses new ones. Same "no real measurement yet" caveat as
 * above. */
#define GW_HEAP_NODE_SHED_BYTES (32u * 1024u)

/* Starts periodic heap-headroom sampling. softap_netif is the netif
 * downlink_softap_init() created (downlink_softap_get_netif()) - its DHCP
 * server is what gets paused/resumed as free heap crosses
 * GW_HEAP_NODE_SHED_BYTES. Pass NULL on a GW_ROLE_RELAY node:
 * downlink_halow_ap.c's netif runs no DHCP server to pause (static IP only -
 * see that file's own header comment), so only the CoT-shed and telemetry
 * halves of this module are meaningful there. */
esp_err_t heap_guard_init(esp_netif_t *softap_netif);

/* True once combined free heap has dropped below GW_HEAP_COT_SHED_BYTES.
 * Checked by cot_relay.c's relay_task before forwarding each datagram. */
bool heap_guard_should_shed_cot(void);

/* Current combined free heap, its low-watermark since boot
 * (esp_get_minimum_free_heap_size()), and current free *internal* SRAM alone
 * (esp_get_free_internal_heap_size() -
 * MALLOC_CAP_8BIT|MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL, which PSRAM can never
 * back since DMA descriptors and task stacks must live on-chip) - all in
 * bytes, for /api/status. Internal-heap headroom is worth surfacing
 * separately even with PSRAM installed: it can run low on its own while the
 * combined figure still looks healthy. Any out pointer may be NULL. */
void heap_guard_get_stats(uint32_t *out_free_bytes, uint32_t *out_min_free_bytes,
                           uint32_t *out_free_internal_bytes);
