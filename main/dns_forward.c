#include <string.h>

#include "dns_forward.h"

#include "esp_check.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "task_stats.h"

static const char *TAG = "dns_forward";

#define DNS_PORT 53

/* DNS messages over UDP are capped at 512 bytes without EDNS0 (RFC 1035
 * §4.2.1); a handful of mesh clients doing ordinary lookups have no reason
 * to need EDNS0's larger messages, and this project doesn't advertise
 * support for it, so a client asking for one gets truncated - correct,
 * standard DNS behavior (the TC bit tells it to retry over TCP), not a bug
 * introduced by capping this buffer here. */
#define DNS_MSG_MAX 512

/* How many queries can be in flight at once, awaiting a reply from the
 * upstream resolver, before the oldest is evicted to make room. A handful
 * of mesh clients doing ordinary lookups will not have this many concurrent
 * outstanding queries in practice - generous headroom, not a tight budget. */
#define DNS_PENDING_MAX 8

/* Drop a pending query if nothing answered it within this long, so a lost
 * reply (or a client that gave up and re-queried with a fresh txn ID)
 * doesn't hold a table slot forever. */
#define DNS_PENDING_TTL_US (5LL * 1000000LL)

typedef struct {
    bool in_use;
    uint16_t txn_id; /* first 2 bytes of a DNS message (RFC 1035 §4.1.1) - not
                       * otherwise parsed; this forwarder is content-agnostic
                       * and just needs to route the matching reply back. */
    struct sockaddr_in leaf_addr;
    int64_t sent_at_us;
} pending_query_t;

static esp_netif_t *s_downlink_netif = NULL;
static esp_netif_t *s_uplink_netif = NULL;
static int s_listen_sock = -1;   /* bound to the downlink's own address, port 53 - leaves query this */
static int s_upstream_sock = -1; /* unbound - used to talk to whatever the uplink's real DNS server is */
static pending_query_t s_pending[DNS_PENDING_MAX];
static bool s_running = false;

static esp_err_t get_netif_addr(esp_netif_t *netif, struct in_addr *out)
{
    esp_netif_ip_info_t ip_info;
    esp_err_t err = esp_netif_get_ip_info(netif, &ip_info);
    if (err != ESP_OK) {
        return err;
    }
    out->s_addr = ip_info.ip.addr;
    return ESP_OK;
}

/* Re-read on every query rather than cached once at startup - a GW_ROLE_RELAY
 * node's own uplink is a normal DHCP client (see dns_forward.h's own
 * comment), so this tracks a lease renewal handing out a different DNS
 * server without needing a restart. Cheap: esp_netif_get_dns_info() reads
 * already-stored state, no network round trip. */
static bool get_upstream_dns_addr(struct sockaddr_in *out)
{
    esp_netif_dns_info_t dns;
    if (esp_netif_get_dns_info(s_uplink_netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK ||
        dns.ip.type != ESP_IPADDR_TYPE_V4 || dns.ip.u_addr.ip4.addr == 0) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons(DNS_PORT);
    out->sin_addr.s_addr = dns.ip.u_addr.ip4.addr;
    return true;
}

static pending_query_t *pending_find(uint16_t txn_id)
{
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (s_pending[i].in_use && s_pending[i].txn_id == txn_id) {
            return &s_pending[i];
        }
    }
    return NULL;
}

/* Evicts the oldest slot if the table is full - matches this project's
 * existing LRU-on-full pattern (main/auth.c's session table) rather than
 * refusing new queries outright while a stuck one lingers. */
static pending_query_t *pending_alloc(void)
{
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (!s_pending[i].in_use) {
            return &s_pending[i];
        }
    }
    int oldest_idx = 0;
    int64_t oldest_time = now;
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (s_pending[i].sent_at_us < oldest_time) {
            oldest_time = s_pending[i].sent_at_us;
            oldest_idx = i;
        }
    }
    return &s_pending[oldest_idx];
}

static void pending_expire_stale(void)
{
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (s_pending[i].in_use && (now - s_pending[i].sent_at_us) > DNS_PENDING_TTL_US) {
            s_pending[i].in_use = false;
        }
    }
}

/* One task, one select() loop over both sockets - this project's own
 * cot_relay.c uses a single shared socket instead because a multicast group
 * join naturally serves both directions on one fd; DNS forwarding is a real
 * two-socket relay (a listener for leaf queries, a separate unconnected
 * socket for talking to whatever the upstream resolver currently is), so
 * select() is what multiplexes them without a task per query or per leaf. */
static void dns_forward_task(void *arg)
{
    (void)arg;
    static uint8_t buf[DNS_MSG_MAX];

    for (;;) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s_listen_sock, &read_fds);
        FD_SET(s_upstream_sock, &read_fds);
        int maxfd = (s_listen_sock > s_upstream_sock) ? s_listen_sock : s_upstream_sock;

        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(maxfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            ESP_LOGW(TAG, "select failed: errno %d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        pending_expire_stale();

        if (ready == 0) {
            continue; /* timeout - just here to run pending_expire_stale() periodically */
        }

        if (FD_ISSET(s_listen_sock, &read_fds)) {
            struct sockaddr_in leaf_addr;
            socklen_t addr_len = sizeof(leaf_addr);
            int len = recvfrom(s_listen_sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&leaf_addr, &addr_len);
            if (len >= 2) {
                struct sockaddr_in upstream_addr;
                if (get_upstream_dns_addr(&upstream_addr)) {
                    pending_query_t *slot = pending_alloc();
                    slot->in_use = true;
                    slot->txn_id = ((uint16_t)buf[0] << 8) | buf[1];
                    slot->leaf_addr = leaf_addr;
                    slot->sent_at_us = esp_timer_get_time();

                    if (sendto(s_upstream_sock, buf, (size_t)len, 0,
                               (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) < 0) {
                        ESP_LOGW(TAG, "forwarding query upstream failed: errno %d", errno);
                        slot->in_use = false;
                    }
                } else {
                    ESP_LOGW(TAG, "no upstream DNS server known yet (uplink not up?) - "
                                  "dropping a query rather than guessing one");
                }
            }
        }

        if (FD_ISSET(s_upstream_sock, &read_fds)) {
            struct sockaddr_in upstream_addr;
            socklen_t addr_len = sizeof(upstream_addr);
            int len = recvfrom(s_upstream_sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&upstream_addr, &addr_len);
            if (len >= 2) {
                uint16_t txn_id = ((uint16_t)buf[0] << 8) | buf[1];
                pending_query_t *slot = pending_find(txn_id);
                if (slot != NULL) {
                    sendto(s_listen_sock, buf, (size_t)len, 0,
                           (struct sockaddr *)&slot->leaf_addr, sizeof(slot->leaf_addr));
                    slot->in_use = false;
                } /* else: reply to a query we've already expired/evicted - drop it */
            }
        }
    }
}

esp_err_t dns_forward_start(esp_netif_t *downlink_netif, esp_netif_t *uplink_netif)
{
    if (downlink_netif == NULL || uplink_netif == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_running) {
        return ESP_ERR_INVALID_STATE; /* already running */
    }

    s_downlink_netif = downlink_netif;
    s_uplink_netif = uplink_netif;
    memset(s_pending, 0, sizeof(s_pending));

    struct in_addr downlink_addr;
    esp_err_t err = get_netif_addr(downlink_netif, &downlink_addr);
    if (err != ESP_OK || downlink_addr.s_addr == 0) {
        ESP_LOGE(TAG, "downlink has no address yet: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }

    s_listen_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_listen_sock < 0) {
        ESP_LOGE(TAG, "listen socket() failed: errno %d", errno);
        return ESP_FAIL;
    }
    struct sockaddr_in bind_addr = { 0 };
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr = downlink_addr;
    bind_addr.sin_port = htons(DNS_PORT);
    if (bind(s_listen_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "bind() on downlink:%d failed: errno %d", DNS_PORT, errno);
        close(s_listen_sock);
        s_listen_sock = -1;
        return ESP_FAIL;
    }

    s_upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_upstream_sock < 0) {
        ESP_LOGE(TAG, "upstream socket() failed: errno %d", errno);
        close(s_listen_sock);
        s_listen_sock = -1;
        return ESP_FAIL;
    }

    if (xTaskCreate(dns_forward_task, "dns_forward", GW_STACK_DNS_FORWARD, NULL, 5, NULL) != pdPASS) {
        close(s_listen_sock);
        close(s_upstream_sock);
        s_listen_sock = -1;
        s_upstream_sock = -1;
        return ESP_ERR_NO_MEM;
    }

    s_running = true;
    esp_ip4_addr_t downlink_ip4 = { .addr = downlink_addr.s_addr };
    ESP_LOGI(TAG, "DNS forwarder listening on " IPSTR ":%d", IP2STR(&downlink_ip4), DNS_PORT);
    return ESP_OK;
}

bool dns_forward_is_running(void)
{
    return s_running;
}
