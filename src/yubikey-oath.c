/**
 * rofi-yubikey-oath
 *
 * MIT License
 * Copyright (c) 2026 Jacques Boscq <jacques@boscq.fr>
 *
 * A rofi plugin that lists OATH TOTP credentials stored on a YubiKey and
 * copies the selected code to the clipboard via wl-copy (Wayland).
 *
 * Build:
 *   meson setup build
 *   meson compile -C build
 *
 * Install:
 *   meson install -C build
 *
 * Usage:
 *   rofi -modi yubikey-oath -show yubikey-oath
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include <gmodule.h>
#include <rofi/mode.h>
#include <rofi/helper.h>
#include <rofi/mode-private.h>

#ifdef HAVE_FONTCONFIG
#include <fontconfig/fontconfig.h>
#endif

/* PC/SC — libpcsclite-dev on Debian/Ubuntu, pcsclite on Arch */
#include <winscard.h>

/* ── Debug / traffic logging ────────────────────────────────────────────── */
/*
 * Set YUBIKEY_OATH_DEBUG=1 in the environment to enable TRAFFIC-level logging
 * to stderr, matching the format of `ykman --log-level TRAFFIC` so the two
 * outputs can be diffed side by side.
 *
 * Example:
 *   YUBIKEY_OATH_DEBUG=1 rofi -modi yubikey-oath -show yubikey-oath 2>plugin.log
 *   ykman --log-level TRAFFIC oath accounts code  2>ykman.log
 *   diff <(grep 'SEND\|RECV\|TRAFFIC\|connect\|SELECT\|CALC' ykman.log) \
 *        <(grep 'SEND\|RECV\|TRAFFIC\|connect\|SELECT\|CALC' plugin.log)
 */

static int yk_debug = -1; /* -1 = uninitialised */

static void
yk_log_init(void)
{
    if (yk_debug == -1)
        yk_debug = (getenv("YUBIKEY_OATH_DEBUG") != NULL);
}

/* Return elapsed milliseconds since first call (monotonic). */
static double
yk_now_ms(void)
{
    static struct timespec t0 = { 0, 0 };
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    if (t0.tv_sec == 0 && t0.tv_nsec == 0)
        t0 = now;
    return (now.tv_sec  - t0.tv_sec ) * 1000.0
         + (now.tv_nsec - t0.tv_nsec) / 1e6;
}

static void
yk_hex(const char *label, const unsigned char *buf, size_t len)
{
    if (!yk_debug) return;
    fprintf(stderr, "TRAFFIC %8.3f [yubikey-oath] %-5s: ", yk_now_ms(), label);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x", buf[i]);
    /* Decode SW at end of RECV for convenience */
    if (strcmp(label, "RECV") == 0 && len >= 2)
        fprintf(stderr, "  SW=%02x%02x", buf[len-2], buf[len-1]);
    fprintf(stderr, "\n");
}

#define YK_LOG(fmt, ...) \
    do { if (yk_debug) fprintf(stderr, "DEBUG  %8.3f [yubikey-oath] " fmt "\n", \
                               yk_now_ms(), ##__VA_ARGS__); } while (0)

/*
 * MARKUP_ROWS is defined in rofi's internal view.h, which is not installed
 * as a public header.  Its value has been stable at 8 since rofi 1.4.
 * Setting this bit in the state parameter of _get_display_value tells rofi
 * to interpret the returned string as Pango markup.
 */
#ifndef MARKUP_ROWS
#define MARKUP_ROWS 8
#endif

/* ── OATH constants ─────────────────────────────────────────────────────── */

#define OATH_AID     "\xa0\x00\x00\x05\x27\x21\x01"
#define OATH_AID_LEN 7

#define INS_SELECT        0xA4
#define INS_CALCULATE     0xA2
#define INS_CALCULATE_ALL 0xA4  /* same opcode; CLA/P1/P2 differ from SELECT */

#define RESPONSE_BUF_SIZE 8192

/* ── TLV helper ─────────────────────────────────────────────────────────── */

typedef struct
{
    unsigned char        tag;
    size_t               length;
    const unsigned char *value;
} TLV;

/**
 * Parse one TLV record at *data.
 * Returns number of bytes consumed, or -1 on error.
 */
static int
parse_tlv(const unsigned char *data, size_t data_len, TLV *tlv)
{
    if (data_len < 2)
        return -1;
    tlv->tag    = data[0];
    tlv->length = data[1];
    if (data_len < 2 + tlv->length)
        return -1;
    tlv->value = data + 2;
    return (int)(2 + tlv->length);
}

/* ── Per-entry data ─────────────────────────────────────────────────────── */

#define ENTRY_NAME_MAX  128
#define ENTRY_CODE_MAX  16

typedef struct
{
    char name[ENTRY_NAME_MAX]; /* raw credential name as returned by YubiKey */
    int  needs_touch;          /* 1 → requires physical touch on CALCULATE   */
} OATHEntry;

/* ── Plugin private data ────────────────────────────────────────────────── */

typedef struct
{
    /*
     * PC/SC handles.
     *
     * context is kept open for the lifetime of the plugin session —
     * it is only a handle to the pcscd daemon and does not hold the
     * USB CCID channel open.
     *
     * card is opened only for the duration of actual APDU exchanges
     * (load_entries at startup, calculate_single_totp on selection)
     * and disconnected immediately afterwards so the YubiKey LED does
     * not stay lit while rofi is idle.
     *
     * readers holds the g_malloc'd reader name string needed by
     * SCardConnect.
     */
    SCARDCONTEXT context;
    SCARDHANDLE  card;
    DWORD        protocol;
    char        *readers;        /* g_malloc'd reader name list          */
    int          pcsc_ok;        /* 0 → failed to init, entries show err */

    /* Credential list */
    OATHEntry   *entries;
    unsigned int entry_count;

    /* Display strings: "🔒 Issuer  <i>login</i>" (Pango markup, MARKUP_ROWS) */
    char       **display;

    /*
     * Touch flow:
     *
     *   _result sets awaiting_touch = 1 and schedules on_touch_idle()
     *   via g_idle_add(), then returns RELOAD_DIALOG.
     *
     *   rofi redraws: _get_num_entries returns 1, _get_display_value
     *   returns the prompt — the user sees "👆 Please touch your YubiKey…".
     *
     *   on_touch_idle() fires on the next idle iteration (after the
     *   redraw), blocks on CALCULATE, copies the code, then calls
     *   exit(0) to close rofi cleanly.
     *
     *   pending_touch_name holds the credential name for the idle cb.
     */
    int  awaiting_touch;
    char pending_touch_name[ENTRY_NAME_MAX];
} YKOATHPrivateData;

G_MODULE_EXPORT Mode mode;

/*
 * If fontconfig is available, initialise it in a library constructor so
 * it is ready before any dependency constructor can call into it
 * implicitly, which would trigger a "using without calling FcInit()"
 * warning on stderr.
 */
#ifdef HAVE_FONTCONFIG
static void __attribute__((constructor))
plugin_init_fontconfig(void)
{
    FcInit();
}
#endif

/* ── Forward declarations ───────────────────────────────────────────────── */
/*
 * Declared here, at the top, so all functions below may call each other
 * freely without depending on textual order.
 */
static int      pcsc_reconnect(YKOATHPrivateData *pd);
static void     pcsc_disconnect(YKOATHPrivateData *pd);
static void     pcsc_teardown(YKOATHPrivateData *pd);
static gboolean on_touch_idle(gpointer user_data);

/* ── PC/SC send/receive ─────────────────────────────────────────────────── */

/**
 * Transmit an APDU and collect the full response, handling SW1=61
 * (more data) continuation automatically.
 *
 * response must point to a buffer of at least RESPONSE_BUF_SIZE bytes.
 * *response_len is updated with the total number of bytes received
 * (including the final SW1SW2 pair).
 *
 * Returns 0 on success, -1 on error.
 */
static int
send_apdu(SCARDHANDLE card, DWORD protocol,
          const unsigned char *apdu, size_t apdu_len,
          unsigned char *response, size_t *response_len)
{
    SCARD_IO_REQUEST pioSendPci;
    DWORD recv_len = (DWORD)*response_len;
    LONG rv;

    switch (protocol)
    {
    case SCARD_PROTOCOL_T0:
        pioSendPci = *SCARD_PCI_T0;
        break;
    case SCARD_PROTOCOL_T1:
        pioSendPci = *SCARD_PCI_T1;
        break;
    default:
        fprintf(stderr, "[yubikey-oath] Unknown PC/SC protocol\n");
        return -1;
    }

    yk_log_init();
    yk_hex("SEND", apdu, apdu_len);

    rv = SCardTransmit(card, &pioSendPci,
                       apdu, (DWORD)apdu_len,
                       NULL, response, &recv_len);
    if (rv != SCARD_S_SUCCESS)
    {
        fprintf(stderr, "[yubikey-oath] SCardTransmit: %s\n",
                pcsc_stringify_error(rv));
        return -1;
    }

    size_t total_len = recv_len;
    yk_hex("RECV", response, total_len);

    /* Handle continuation frames (SW1 == 0x61) */
    while (total_len >= 2 && response[total_len - 2] == 0x61)
    {
        unsigned char remaining = response[total_len - 1];
        size_t data_so_far = total_len - 2;

        /* Make sure we do not overflow the buffer */
        if (data_so_far + remaining + 2 > *response_len)
        {
            fprintf(stderr, "[yubikey-oath] response buffer too small\n");
            return -1;
        }

        unsigned char get_resp[] = { 0x00, 0xC0, 0x00, 0x00, remaining };
        DWORD get_len = remaining;

        YK_LOG("GET RESPONSE for %u more bytes", remaining);
        yk_hex("SEND", get_resp, sizeof(get_resp));

        rv = SCardTransmit(card, &pioSendPci,
                           get_resp, sizeof(get_resp),
                           NULL, response + data_so_far, &get_len);
        if (rv != SCARD_S_SUCCESS)
        {
            fprintf(stderr, "[yubikey-oath] GET RESPONSE: %s\n",
                    pcsc_stringify_error(rv));
            return -1;
        }

        total_len = data_so_far + get_len;
        yk_hex("RECV", response, total_len);
    }

    *response_len = total_len;
    return 0;
}

/* ── OATH helpers ───────────────────────────────────────────────────────── */

static int
select_oath_app(SCARDHANDLE card, DWORD protocol)
{
    unsigned char apdu[5 + OATH_AID_LEN];
    unsigned char response[256];
    size_t response_len = sizeof(response);

    apdu[0] = 0x00;
    apdu[1] = INS_SELECT;
    apdu[2] = 0x04;
    apdu[3] = 0x00;
    apdu[4] = OATH_AID_LEN;
    memcpy(apdu + 5, OATH_AID, OATH_AID_LEN);

    YK_LOG("Selecting OATH AID a0000005272101");
    if (send_apdu(card, protocol, apdu, sizeof(apdu), response, &response_len))
        return -1;

    if (response_len < 2 ||
        response[response_len - 2] != 0x90 ||
        response[response_len - 1] != 0x00)
    {
        fprintf(stderr, "[yubikey-oath] SELECT OATH failed: %02X%02X\n",
                response[response_len - 2], response[response_len - 1]);
        return -1;
    }

    /* Decode firmware version from SELECT response (tag 0x79 length 3 = version) */
    if (yk_debug && response_len > 4)
    {
        size_t i = 0;
        while (i + 1 < response_len - 2)
        {
            unsigned char tag = response[i];
            unsigned char len = response[i+1];
            if (tag == 0x79 && len >= 3 && i + 2 + len <= response_len - 2)
                YK_LOG("OATH session initialised (version=%u.%u.%u)",
                       response[i+2], response[i+3], response[i+4]);
            i += 2 + len;
        }
    }
    return 0;
}

/**
 * Build a Pango-markup display string from a raw YubiKey credential name.
 *
 * YubiKey Authenticator stores names as "Issuer:login" (the colon is the
 * OATH spec separator).  We render them as:
 *
 *   🔒 Issuer  <i>login</i>          (touch-required)
 *   Issuer  <i>login</i>             (code available on demand)
 *
 * If there is no colon the whole name is shown as-is, without italic.
 * Special Pango characters in issuer/login are escaped so markup is safe.
 *
 * Returns a g_malloc'd string; caller owns it.
 */
static char *
build_display(const char *name, int needs_touch)
{
    const char *colon = strchr(name, ':');
    char *issuer_esc, *login_esc, *result;

    if (colon)
    {
        char *issuer = g_strndup(name, (gsize)(colon - name));
        issuer_esc   = g_markup_escape_text(issuer, -1);
        login_esc    = g_markup_escape_text(colon + 1, -1);
        g_free(issuer);

        if (needs_touch)
            result = g_strdup_printf("🔒 %s  <i>%s</i>", issuer_esc, login_esc);
        else
            result = g_strdup_printf("%s  <i>%s</i>", issuer_esc, login_esc);

        g_free(login_esc);
    }
    else
    {
        issuer_esc = g_markup_escape_text(name, -1);

        if (needs_touch)
            result = g_strdup_printf("🔒 %s", issuer_esc);
        else
            result = g_strdup(issuer_esc);
    }

    g_free(issuer_esc);
    return result;
}

/**
 * Run LIST (via CALCULATE ALL with a dummy challenge) to enumerate credential
 * names, then populate pd->entries / pd->display.
 *
 * Must be called after select_oath_app().
 */
static void
load_entries(YKOATHPrivateData *pd)
{
    unsigned char apdu[32];
    unsigned char response[RESPONSE_BUF_SIZE];
    size_t response_len = sizeof(response);

    uint64_t ts_real = (uint64_t)time(NULL) / 30;
    unsigned char challenge[8];
    for (int i = 7; i >= 0; i--)
    {
        challenge[i] = ts_real & 0xFF;
        ts_real >>= 8;
    }
    YK_LOG("CALCULATE ALL: timestamp=%" PRIu64, (uint64_t)time(NULL) / 30);

    size_t apdu_len = 0;
    apdu[apdu_len++] = 0x00;              /* CLA                          */
    apdu[apdu_len++] = INS_CALCULATE_ALL; /* INS 0xA4                     */
    apdu[apdu_len++] = 0x00;              /* P1                           */
    apdu[apdu_len++] = 0x01;              /* P2 = 0x01: full response     */
    apdu[apdu_len++] = 0x00;              /* Extended APDU marker         */
    apdu[apdu_len++] = 0x00;              /* Lc high byte                 */
    apdu[apdu_len++] = 10;                /* Lc low byte (10 bytes)       */
    apdu[apdu_len++] = 0x74;              /* Challenge tag                */
    apdu[apdu_len++] = 8;                 /* Challenge length             */
    memcpy(apdu + apdu_len, challenge, 8);
    apdu_len += 8;
    /* No Le field — matches ykman behaviour */

    double t_before = yk_now_ms();
    if (send_apdu(pd->card, pd->protocol, apdu, apdu_len,
                  response, &response_len) != 0)
        return;
    YK_LOG("CALCULATE ALL round-trip: %.1f ms", yk_now_ms() - t_before);

    unsigned char sw1 = response[response_len - 2];
    unsigned char sw2 = response[response_len - 1];

    /* 90 00 = complete, 61 XX = more data (already fetched by send_apdu) */
    if (sw1 != 0x90 && sw1 != 0x61)
    {
        fprintf(stderr, "[yubikey-oath] CALCULATE ALL failed: %02X%02X\n",
                sw1, sw2);
        return;
    }

    /* First pass: count entries */
    unsigned int count = 0;
    size_t pos = 0;

    while (pos < response_len - 2)
    {
        TLV name_tlv, code_tlv;
        int c = parse_tlv(response + pos, response_len - 2 - pos, &name_tlv);
        if (c < 0 || name_tlv.tag != 0x71)
            break;
        pos += c;
        c = parse_tlv(response + pos, response_len - 2 - pos, &code_tlv);
        if (c < 0)
            break;
        pos += c;
        count++;
    }
    if (count == 0)
        return;

    pd->entries     = g_malloc0(count * sizeof(OATHEntry));
    pd->display     = g_malloc0(count * sizeof(char *));
    pd->entry_count = 0;

    /* Second pass: fill entries */
    pos = 0;
    while (pos < response_len - 2 && pd->entry_count < count)
    {
        TLV name_tlv, code_tlv;
        int c = parse_tlv(response + pos, response_len - 2 - pos, &name_tlv);
        if (c < 0 || name_tlv.tag != 0x71)
            break;
        pos += c;
        c = parse_tlv(response + pos, response_len - 2 - pos, &code_tlv);
        if (c < 0)
            break;
        pos += c;

        OATHEntry *e = &pd->entries[pd->entry_count];

        size_t nlen = name_tlv.length < ENTRY_NAME_MAX - 1
                      ? name_tlv.length : ENTRY_NAME_MAX - 1;
        memcpy(e->name, name_tlv.value, nlen);
        e->name[nlen] = '\0';

        /*
         * Response tags differ by P2 mode:
         *   P2=0x00 (name-only, no HMAC):
         *     0x75 → credential exists, no touch required
         *     0x77 → HOTP or touch-required TOTP
         *     0x7C → touch-only TOTP (explicit)
         *   P2=0x01 (full response, HMAC computed):
         *     0x76 → code computed inline, no touch required
         *     0x77 → HOTP or touch-required TOTP
         *     0x7C → touch-only TOTP (explicit)
         *
         * With P2=0x01, the YubiKey computes codes inline for no-touch
         * credentials and returns them with tag 0x76.
         * Touch-required credentials return tag 0x7C.
         */
        e->needs_touch = (code_tlv.tag != 0x76);

        YK_LOG("entry[%u] tag=0x%02x needs_touch=%d name='%s'",
               pd->entry_count, code_tlv.tag, e->needs_touch, e->name);

        pd->display[pd->entry_count] = build_display(e->name, e->needs_touch);
        pd->entry_count++;
    }
}

/**
 * Calculate TOTP for a single credential by name.
 * Returns a g_malloc'd string the caller must g_free(), or NULL on error.
 * For touch-required credentials this call blocks until the key is touched.
 */
static char *
calculate_single_totp(YKOATHPrivateData *pd, const char *credential_name)
{
    unsigned char apdu[256];
    unsigned char response[256];
    size_t response_len = sizeof(response);

    size_t name_len = strlen(credential_name);

    /* Guard against a crafted/corrupt credential name overflowing the APDU
     * buffer: 7 fixed header bytes + name + 2 challenge tag/len + 8 challenge
     * data = 17 + name_len bytes total. */
    if (17 + name_len > sizeof(apdu))
    {
        fprintf(stderr,
            "[yubikey-oath] credential name too long (%zu bytes)\n", name_len);
        return NULL;
    }

    uint64_t timestamp = (uint64_t)time(NULL) / 30;
    unsigned char challenge[8];

    for (int i = 7; i >= 0; i--)
    {
        challenge[i] = timestamp & 0xFF;
        timestamp >>= 8;
    }

    YK_LOG("CALCULATE '%s' timestamp=%" PRIu64, credential_name,
           (uint64_t)time(NULL) / 30);

    size_t apdu_len = 0;
    size_t lc_value = 2 + name_len + 2 + 8;  /* name TLV + challenge TLV */

    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = INS_CALCULATE;
    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = 0x01;            /* request full (truncated) response */
    apdu[apdu_len++] = 0x00;            /* Extended APDU marker              */
    apdu[apdu_len++] = (unsigned char)(lc_value >> 8);   /* Lc high byte     */
    apdu[apdu_len++] = (unsigned char)(lc_value & 0xFF); /* Lc low byte      */
    apdu[apdu_len++] = 0x71;            /* Name tag                          */
    apdu[apdu_len++] = (unsigned char)name_len;
    memcpy(apdu + apdu_len, credential_name, name_len);
    apdu_len += name_len;
    apdu[apdu_len++] = 0x74;            /* Challenge tag                     */
    apdu[apdu_len++] = 8;               /* Challenge length                  */
    memcpy(apdu + apdu_len, challenge, 8);
    apdu_len += 8;
    /* No Le field — matches ykman behaviour */

    if (send_apdu(pd->card, pd->protocol, apdu, apdu_len,
                  response, &response_len) != 0)
        return NULL;

    if (response_len < 2 || response[response_len - 2] != 0x90 ||
        response[response_len - 1] != 0x00)
    {
        fprintf(stderr, "[yubikey-oath] CALCULATE failed for '%s': %02X%02X\n",
                credential_name,
                response[response_len - 2], response[response_len - 1]);
        return NULL;
    }

    size_t pos = 0;
    while (pos < response_len - 2)
    {
        TLV tlv;
        int consumed = parse_tlv(response + pos, response_len - 2 - pos, &tlv);

        if (consumed < 0)
            break;
        if (tlv.tag == 0x76 && tlv.length >= 5)
        {
            unsigned int digits = tlv.value[0];
            if (digits == 0 || digits > ENTRY_CODE_MAX - 1)
                digits = 6;
            uint32_t code = 0;
            for (int i = 1; i < 5; i++)
                code = (code << 8) | tlv.value[i];
            uint32_t divisor = 1;
            for (unsigned int i = 0; i < digits; i++)
                divisor *= 10;
            code %= divisor;
            char *result = g_strdup_printf("%0*u", digits, code);
            YK_LOG("CALCULATE result: %s (%u digits)", result, digits);
            return result;
        }
        pos += consumed;
    }
    YK_LOG("CALCULATE: no 0x76 response tag found in reply");
    return NULL;
}

/* ── Clipboard helper ───────────────────────────────────────────────────── */

static void
copy_to_clipboard(const char *text)
{
    FILE *pipe = popen("wl-copy", "w");
    if (!pipe)
    {
        fprintf(stderr, "[yubikey-oath] popen(wl-copy) failed: %s\n",
                strerror(errno));
        return;
    }
    if (fprintf(pipe, "%s", text) < 0)
        fprintf(stderr, "[yubikey-oath] write to wl-copy failed\n");
    pclose(pipe);
}

/**
 * Drop the SCardHandle (CCID channel) without releasing the SCardContext.
 * Safe to call even when pd->card is already 0.
 */
static void
pcsc_disconnect(YKOATHPrivateData *pd)
{
    if (pd->card)
    {
        YK_LOG("SCardDisconnect (SCARD_UNPOWER_CARD)");
        SCardDisconnect(pd->card, SCARD_UNPOWER_CARD);
        pd->card = 0;
        pd->protocol = 0;
        YK_LOG("card disconnected — LED should be off now");
    }
}

/* ── Touch idle callback ────────────────────────────────────────────────── */

/*
 * Fired by GLib on the first idle iteration after _result returns
 * RELOAD_DIALOG.  By this point rofi has redrawn and the "👆 Please touch your
 * YubiKey…" prompt is on screen.  We reconnect here, block on the CALCULATE
 * APDU, copy the resulting code to the clipboard, then exit the process
 * cleanly.
 *
 * Using exit() rather than a rofi API is intentional: there is no public
 * symbol that closes rofi from outside its _result callback, and calling
 * exit() from a GLib idle source is well-defined — atexit handlers and
 * GLib cleanup both run normally.
 */
static gboolean
on_touch_idle(gpointer user_data)
{
    YKOATHPrivateData *pd = (YKOATHPrivateData *)user_data;

    if (pcsc_reconnect(pd) != 0)
    {
        fprintf(stderr,
                "[yubikey-oath] on_touch_idle: failed to reconnect\n");
        exit(1);
    }

    YK_LOG("on_touch_idle: connected, blocking on CALCULATE for '%s'",
           pd->pending_touch_name);
    double t0 = yk_now_ms();
    char *code = calculate_single_totp(pd, pd->pending_touch_name);
    YK_LOG("on_touch_idle: CALCULATE returned in %.1f ms", yk_now_ms() - t0);
    pcsc_disconnect(pd);
    if (code)
    {
        copy_to_clipboard(code);
        g_free(code);
    }

    exit(0);
    return G_SOURCE_REMOVE;   /* never reached, but satisfies the type */
}

/* ── PC/SC initialisation / teardown ───────────────────────────────────── */

/**
 * Open a fresh SCardConnect to the YubiKey and select the OATH application.
 * Must only be called when pd->card is not already open (i.e. after init or
 * after a pcsc_disconnect).
 *
 * Returns 0 on success, -1 on error.
 */
static int
pcsc_reconnect(YKOATHPrivateData *pd)
{
    LONG rv;

    YK_LOG("SCardConnect reader='%s'", pd->readers);
    double t_conn = yk_now_ms();
    rv = SCardConnect(pd->context, pd->readers,
                            SCARD_SHARE_EXCLUSIVE,
                            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                            &pd->card, &pd->protocol);
    if (rv != SCARD_S_SUCCESS)
    {
        fprintf(stderr, "[yubikey-oath] SCardConnect (reconnect): %s\n",
                pcsc_stringify_error(rv));
        pd->card     = 0;
        pd->protocol = 0;
        return -1;
    }
    YK_LOG("SCardConnect OK in %.1f ms, protocol=T%s",
           yk_now_ms() - t_conn,
           pd->protocol == SCARD_PROTOCOL_T1 ? "1" :
           pd->protocol == SCARD_PROTOCOL_T0 ? "0" : "?");
    if (pd->protocol != SCARD_PROTOCOL_T1 &&
        pd->protocol != SCARD_PROTOCOL_T0)
    {
        fprintf(stderr, "[yubikey-oath] Unknown PC/SC protocol\n");
        pcsc_disconnect(pd);
        return -1;
    }

    if (select_oath_app(pd->card, pd->protocol) != 0)
    {
        fprintf(stderr,
                "[yubikey-oath] SELECT OATH failed after reconnect\n");
        SCardDisconnect(pd->card, SCARD_UNPOWER_CARD);
        pd->card     = 0;
        pd->protocol = 0;
        return -1;
    }

    return 0;
}

static void
pcsc_teardown(YKOATHPrivateData *pd)
{
    if (pd->pcsc_ok)
    {
        pcsc_disconnect(pd);          /* no-op if already disconnected */
        SCardReleaseContext(pd->context);
    }
    g_free(pd->readers);
    pd->readers = NULL;
}

/* ── Rofi mode callbacks ────────────────────────────────────────────────── */

static int
myplugin_mode_init(Mode *sw)
{
    if (mode_get_private_data(sw) != NULL)
        return TRUE;

    yk_log_init();
    YK_LOG("=== yubikey-oath plugin init (pid=%d) ===", (int)getpid());

    YKOATHPrivateData *pd = g_malloc0(sizeof(*pd));
    mode_set_private_data(sw, pd);

    /* Only establish context, do NOT connect to the card yet */
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pd->context);
    if (rv != SCARD_S_SUCCESS)
    {
        pd->pcsc_ok = 0;
        return TRUE;
    }

    /* List readers once (optional, keeps readers string ready) */
    DWORD readers_len = 0;
    rv = SCardListReaders(pd->context, NULL, NULL, &readers_len);
    if (rv != SCARD_S_SUCCESS || readers_len == 0)
    {
        pd->pcsc_ok = 0;
        SCardReleaseContext(pd->context);
        pd->context = 0;
        return TRUE;
    }

    pd->readers = g_malloc(readers_len);
    rv = SCardListReaders(pd->context, NULL, pd->readers, &readers_len);
    if (rv != SCARD_S_SUCCESS)
    {
        g_free(pd->readers);
        pd->readers = NULL;
        SCardReleaseContext(pd->context);
        pd->context = 0;
        pd->pcsc_ok = 0;
        return TRUE;
    }

    pd->pcsc_ok = 1;

    /* defer pcsc_reconnect + load_entries until user selects an entry */
    return TRUE;
}

static unsigned int
myplugin_mode_get_num_entries(const Mode *sw)
{
    YKOATHPrivateData *pd = (YKOATHPrivateData *)mode_get_private_data(sw);

    if (!pd->entries)
    {
        /* lazily connect + enumerate credentials */
        YK_LOG("lazy load: connecting + enumerating credentials");
        double t0 = yk_now_ms();
        if (pcsc_reconnect(pd) == 0)
        {
            load_entries(pd);
            pcsc_disconnect(pd);
            YK_LOG("lazy load complete: %u entries in %.1f ms",
                   pd->entry_count, yk_now_ms() - t0);
        }
        else
        {
            /* fallback: display error if YubiKey missing */
            pd->entries     = g_malloc0(sizeof(OATHEntry));
            pd->display     = g_malloc0(sizeof(char *));
            pd->entry_count = 1;
            strncpy(pd->entries[0].name, "Error: YubiKey not found",
                    ENTRY_NAME_MAX - 1);
            pd->entries[0].needs_touch = 0;
            pd->display[0] = g_strdup("Error: YubiKey not found");
        }
    }

    if (pd->awaiting_touch)
        return 1;

    return pd->entry_count;
}

static ModeMode
myplugin_mode_result(Mode *sw, int mretv, G_GNUC_UNUSED char **input,
                     unsigned int selected_line)
{
    YKOATHPrivateData *pd = (YKOATHPrivateData *)mode_get_private_data(sw);

    if (mretv & MENU_NEXT)
        return NEXT_DIALOG;
    if (mretv & MENU_PREVIOUS)
        return PREVIOUS_DIALOG;
    if (mretv & MENU_QUICK_SWITCH)
        return (ModeMode)(mretv & MENU_LOWER_MASK);

    if ((mretv & MENU_OK) && pd->pcsc_ok && selected_line < pd->entry_count)
    {

        OATHEntry *e = &pd->entries[selected_line];

        if (!e->needs_touch)
        {
            /* No touch needed: reconnect, calculate, disconnect, exit. */
            if (pcsc_reconnect(pd) == 0)
            {
                char *code = calculate_single_totp(pd, e->name);
                pcsc_disconnect(pd);
                if (code)
                {
                    copy_to_clipboard(code);
                    g_free(code);
                }
            }
            return MODE_EXIT;
        }

        /*
         * Touch required:
         *
         * 1. Set awaiting_touch so the next redraw shows the prompt.
         * 2. Schedule on_touch_idle() to run after rofi has redrawn.
         * 3. Return RELOAD_DIALOG — rofi redraws (prompt visible), then
         *    the GLib main loop picks up the idle source and calls
         *    on_touch_idle(), which reconnects, blocks on CALCULATE,
         *    and exits.
         */
        pd->awaiting_touch = 1;
        strncpy(pd->pending_touch_name, e->name, ENTRY_NAME_MAX - 1);
        pd->pending_touch_name[ENTRY_NAME_MAX - 1] = '\0';

        g_timeout_add(10, on_touch_idle, pd);

        return RELOAD_DIALOG;
    }

    if (mretv & MENU_ENTRY_DELETE)
        return RELOAD_DIALOG;

    return MODE_EXIT;
}

static void
myplugin_mode_destroy(Mode *sw)
{
    YKOATHPrivateData *pd = (YKOATHPrivateData *)mode_get_private_data(sw);
    if (pd == NULL)
        return;

    pcsc_teardown(pd);

    for (unsigned int i = 0; i < pd->entry_count; i++)
        g_free(pd->display[i]);
    g_free(pd->display);
    g_free(pd->entries);

    g_free(pd);
    mode_set_private_data(sw, NULL);
}

static char *
_get_display_value(const Mode *sw, unsigned int selected_line,
                   int *state,
                   G_GNUC_UNUSED GList **attr_list,
                   int get_entry)
{
    const YKOATHPrivateData *pd =
        (const YKOATHPrivateData *)mode_get_private_data(sw);

    /* Tell rofi to interpret Pango markup in our display strings */
    if (state)
        *state |= MARKUP_ROWS;

    if (!get_entry)
        return NULL;
    if (pd->awaiting_touch)
        return g_strdup("👆 Please touch your YubiKey…");
    if (selected_line >= pd->entry_count)
        return g_strdup("n/a");
    return g_strdup(pd->display[selected_line]);
}

static int
myplugin_token_match(const Mode *sw, rofi_int_matcher **tokens,
                     unsigned int index)
{
    const YKOATHPrivateData *pd =
        (const YKOATHPrivateData *)mode_get_private_data(sw);

    /*
     * While we are waiting for a YubiKey touch, _get_num_entries returns 1
     * and _get_display_value returns the "👆 Please touch your YubiKey…"
     * prompt for index 0.  We must always report this synthetic row as a
     * match, otherwise rofi filters it out when the search bar is non-empty
     * and the prompt disappears from view.
     */
    if (pd->awaiting_touch)
        return 1;

    if (index >= pd->entry_count)
        return 0;
    return helper_token_match(tokens, pd->entries[index].name);
}

/* ── Mode descriptor ────────────────────────────────────────────────────── */

Mode mode = {
    .abi_version        = ABI_VERSION,
    .name               = "yubikey-oath",
    .cfg_name_key       = "display-yubikey-oath",
    .type               = MODE_TYPE_SWITCHER,
    ._init              = myplugin_mode_init,
    ._get_num_entries   = myplugin_mode_get_num_entries,
    ._result            = myplugin_mode_result,
    ._destroy           = myplugin_mode_destroy,
    ._token_match       = myplugin_token_match,
    ._get_display_value = _get_display_value,
    ._get_message       = NULL,
    ._get_completion    = NULL,
    ._preprocess_input  = NULL,
    .private_data       = NULL,
    .free               = NULL,
};
