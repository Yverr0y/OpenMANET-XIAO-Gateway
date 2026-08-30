#!/usr/bin/env python3
"""Reapplies a local, upstream-reported-bug workaround to the vendored
morsemicro/halow component after the ESP-IDF component manager fetches it.

Why this exists: mmwlan_tx_pkt() (morselib's umac.c) cannot infer which VIF
to transmit on when a GW_ROLE_RELAY node's HaLow AP is up alongside the STA
scaffold mmhalow_init() always creates, and drops the packet instead -
silently blocking essentially all downstream (relay -> leaf) traffic
whenever a relay's AP is active, confirmed on real hardware 2026-08-30 (see
design/ROADMAP.md item under "Web UI authentication" neighbours, and
~/morse-micro-bug-reports.md "Issue 1"). mmhalow.c/.h are Apache-2.0
licensed by Morse Micro (confirmed via their own SPDX headers) - freely
modifiable for local use - but managed_components/ is gitignored and
re-fetched by the component manager on a clean checkout or dependency
version bump, so a one-off hand-edit does not survive that. This script
makes the same edit idempotently, every configure.

Remove this entire mechanism once Morse Micro ships a real fix (their own
CONFIG_MM_* version banner already used elsewhere in this project would be
the thing to check before assuming it's still needed).
"""
import sys

MARKER = "LOCAL PATCH (OpenMANET-XIAO-Gateway"

HEADER_PATH = "managed_components/morsemicro__halow/mmhalow.h"
HEADER_OLD = """typedef struct mmhalow_netif_driver
{
    esp_netif_driver_base_t base;

    struct mmwlan_sta_args sta_args;
    struct mmwlan_ap_args ap_args;

    bool sta_conf_set;
} mmhalow_netif_driver_t;"""
HEADER_NEW = """typedef struct mmhalow_netif_driver
{
    esp_netif_driver_base_t base;

    struct mmwlan_sta_args sta_args;
    struct mmwlan_ap_args ap_args;

    bool sta_conf_set;

    /* LOCAL PATCH (OpenMANET-XIAO-Gateway, 2026-08-30) - see halow_transmit()
     * in mmhalow.c for why this exists: mmwlan_tx_pkt() cannot infer the VIF
     * when both the STA scaffold mmhalow_init() always creates and an
     * AP enabled via mmhalow_wifi_start() are simultaneously valid, and
     * returns MMWLAN_VIF_ERROR - silently dropping every packet this shared
     * transmit path sends while a GW_ROLE_RELAY node's AP is up. Set true by
     * mmhalow_wifi_start() right before mmwlan_ap_enable(); halow_transmit()
     * reads it to pass an explicit vif instead of leaving one for the
     * driver to guess at. Reported upstream (see ~/morse-micro-bug-reports.md,
     * "Issue 1") - remove this once Morse Micro ships a real fix. */
    bool ap_mode_enabled;
} mmhalow_netif_driver_t;"""

SOURCE_PATH = "managed_components/morsemicro__halow/mmhalow.c"
SOURCE_OLD_TRANSMIT = """static esp_err_t halow_transmit(void *h, void *buffer, size_t len)
{
    struct mmpkt *pkt;
    struct mmpktview *pktview;
    enum mmwlan_status status;
    struct mmwlan_tx_metadata metadata = {
        .tid = 0,
    };"""
SOURCE_NEW_TRANSMIT = """static esp_err_t halow_transmit(void *h, void *buffer, size_t len)
{
    struct mmpkt *pkt;
    struct mmpktview *pktview;
    enum mmwlan_status status;
    /* LOCAL PATCH (OpenMANET-XIAO-Gateway, 2026-08-30) - see ap_mode_enabled's
     * own comment in mmhalow.h. Without this, .vif defaults to
     * MMWLAN_VIF_UNSPECIFIED and mmwlan_tx_pkt() (umac.c) cannot infer it
     * whenever a GW_ROLE_RELAY node's AP is up alongside the STA scaffold
     * mmhalow_init() always creates - it returns MMWLAN_VIF_ERROR and this
     * function silently drops the packet. Reported upstream; remove this
     * once fixed there. */
    mmhalow_netif_driver_t *drv = (mmhalow_netif_driver_t *)h;
    struct mmwlan_tx_metadata metadata = {
        .tid = 0,
        .vif = (drv != NULL && drv->ap_mode_enabled) ? MMWLAN_VIF_AP : MMWLAN_VIF_STA,
    };"""

SOURCE_OLD_START = """void mmhalow_wifi_start(){
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    mmwlan_ap_enable(&morse_drv->ap_args);
}"""
SOURCE_NEW_START = """void mmhalow_wifi_start(){
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    /* LOCAL PATCH (OpenMANET-XIAO-Gateway, 2026-08-30) - see
     * ap_mode_enabled's own comment in mmhalow.h. Set before
     * mmwlan_ap_enable() so halow_transmit() sees it on the very first
     * packet this radio sends in AP mode. */
    morse_drv->ap_mode_enabled = true;
    mmwlan_ap_enable(&morse_drv->ap_args);
}"""


def patch_file(path, replacements):
    with open(path, "r") as f:
        content = f.read()

    if MARKER in content:
        return False  # already patched

    for old, new in replacements:
        if old not in content:
            sys.stderr.write(
                "patch_vendored_halow.py: expected text not found in %s - "
                "the vendored file has changed shape (a component version "
                "bump?) and this patch needs re-verifying by hand before it "
                "can be reapplied blindly. Failing loudly rather than "
                "silently skipping the fix.\n%s\n" % (path, old[:200])
            )
            sys.exit(1)
        content = content.replace(old, new, 1)

    with open(path, "w") as f:
        f.write(content)
    return True


def main():
    header_patched = patch_file(HEADER_PATH, [(HEADER_OLD, HEADER_NEW)])
    source_patched = patch_file(
        SOURCE_PATH,
        [
            (SOURCE_OLD_TRANSMIT, SOURCE_NEW_TRANSMIT),
            (SOURCE_OLD_START, SOURCE_NEW_START),
        ],
    )
    if header_patched or source_patched:
        print("patch_vendored_halow.py: applied the VIF-inference workaround "
              "to the freshly fetched morsemicro__halow component")
    else:
        print("patch_vendored_halow.py: already applied, nothing to do")


if __name__ == "__main__":
    main()
