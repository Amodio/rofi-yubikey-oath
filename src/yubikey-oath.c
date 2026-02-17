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

#include <gmodule.h>
#include <rofi/mode.h>
#include <rofi/helper.h>
#include <rofi/mode-private.h>

/* PC/SC — libpcsclite-dev on Debian/Ubuntu, pcsclite on Arch */
#include <winscard.h>

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
#define INS_CALCULATE_ALL 0xA4   /* same opcode; CLA/P1/P2 differ from SELECT */

#define RESPONSE_BUF_SIZE 8192

/* ── TLV helper ─────────────────────────────────────────────────────────── */

typedef struct {
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

typedef struct {
    char name[ENTRY_NAME_MAX];   /* raw credential name as returned by YubiKey  */
    int  needs_touch;            /* 1 → requires physical touch on CALCULATE    */
} OATHEntry;

/* ── Plugin private data ────────────────────────────────────────────────── */

typedef struct {
    /* PC/SC handles — kept open for the lifetime of the plugin session */
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
} YKOATHPrivateData;

G_MODULE_EXPORT Mode mode;

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

    switch (protocol) {
    case SCARD_PROTOCOL_T0: pioSendPci = *SCARD_PCI_T0; break;
    case SCARD_PROTOCOL_T1: pioSendPci = *SCARD_PCI_T1; break;
    default:
        fprintf(stderr, "[yubikey-oath] Unknown PC/SC protocol\n");
        return -1;
    }

    rv = SCardBeginTransaction(card);
    if (rv != SCARD_S_SUCCESS)
        fprintf(stderr, "[yubikey-oath] SCardBeginTransaction: %s (continuing)\n",
                pcsc_stringify_error(rv));

    rv = SCardTransmit(card, &pioSendPci,
                       apdu, (DWORD)apdu_len,
                       NULL, response, &recv_len);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "[yubikey-oath] SCardTransmit: %s\n",
                pcsc_stringify_error(rv));
        SCardEndTransaction(card, SCARD_LEAVE_CARD);
        return -1;
    }
    *response_len = recv_len;

    /* Collect continuation frames (SW1 == 0x61 means more data) */
    while (recv_len >= 2 && response[recv_len - 2] == 0x61) {
        unsigned char remaining   = response[recv_len - 1];
        size_t        data_so_far = recv_len - 2;

        unsigned char get_resp[] = { 0x00, 0xC0, 0x00, 0x00, remaining };
        DWORD get_len = 4096;
        unsigned char get_buf[4096];

        rv = SCardTransmit(card, &pioSendPci,
                           get_resp, sizeof(get_resp),
                           NULL, get_buf, &get_len);
        if (rv != SCARD_S_SUCCESS) {
            fprintf(stderr, "[yubikey-oath] GET RESPONSE: %s\n",
                    pcsc_stringify_error(rv));
            SCardEndTransaction(card, SCARD_LEAVE_CARD);
            return -1;
        }

        /* 6D 00 → GET RESPONSE not supported by this firmware */
        if (get_len >= 2 &&
            get_buf[get_len - 2] == 0x6D &&
            get_buf[get_len - 1] == 0x00) {
            fprintf(stderr,
                "[yubikey-oath] GET RESPONSE unsupported — "
                "showing partial results (%zu bytes)\n", data_so_far);
            break;
        }

        if (data_so_far + get_len > RESPONSE_BUF_SIZE) {
            fprintf(stderr, "[yubikey-oath] Response buffer overflow\n");
            SCardEndTransaction(card, SCARD_LEAVE_CARD);
            return -1;
        }

        memcpy(response + data_so_far, get_buf, get_len);
        recv_len      = get_len;
        *response_len = data_so_far + get_len;
    }

    SCardEndTransaction(card, SCARD_LEAVE_CARD);
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

    if (send_apdu(card, protocol, apdu, sizeof(apdu), response, &response_len) != 0)
        return -1;

    if (response_len < 2 ||
        response[response_len - 2] != 0x90 ||
        response[response_len - 1] != 0x00) {
        fprintf(stderr, "[yubikey-oath] SELECT OATH failed: %02X%02X\n",
                response[response_len - 2], response[response_len - 1]);
        return -1;
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

    if (colon) {
        /* Split on the first colon */
        char *issuer = g_strndup(name, (gsize)(colon - name));
        issuer_esc   = g_markup_escape_text(issuer, -1);
        login_esc    = g_markup_escape_text(colon + 1, -1);
        g_free(issuer);

        if (needs_touch)
            result = g_strdup_printf("🔒 %s  <i>%s</i>", issuer_esc, login_esc);
        else
            result = g_strdup_printf("%s  <i>%s</i>", issuer_esc, login_esc);

        g_free(login_esc);
    } else {
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
 * Codes are never computed here — they are requested on demand when the user
 * selects an entry.  Must be called after select_oath_app().
 */
static void
load_entries(YKOATHPrivateData *pd)
{
    unsigned char apdu[32];
    unsigned char response[RESPONSE_BUF_SIZE];
    size_t response_len = sizeof(response);

    /*
     * We still use CALCULATE ALL so the card tells us which credentials
     * require touch (tag 0x77 / 0x7C) vs which ones it would compute
     * directly (tag 0x76).  A zero challenge is fine — we discard the
     * codes immediately.
     */
    unsigned char challenge[8] = { 0 };

    size_t apdu_len = 0;
    apdu[apdu_len++] = 0x00;              /* CLA                    */
    apdu[apdu_len++] = INS_CALCULATE_ALL; /* INS 0xA4               */
    apdu[apdu_len++] = 0x00;              /* P1                     */
    apdu[apdu_len++] = 0x01;              /* P2 – full response     */
    apdu[apdu_len++] = 0x00;             /* Extended APDU marker    */
    apdu[apdu_len++] = 0x00;             /* Lc high byte            */
    apdu[apdu_len++] = 10;               /* Lc low byte (10 bytes)  */
    apdu[apdu_len++] = 0x74;             /* Challenge tag           */
    apdu[apdu_len++] = 8;                /* Challenge length        */
    memcpy(apdu + apdu_len, challenge, 8);
    apdu_len += 8;

    if (send_apdu(pd->card, pd->protocol, apdu, apdu_len,
                  response, &response_len) != 0)
        return;

    unsigned char sw1 = response[response_len - 2];
    unsigned char sw2 = response[response_len - 1];

    /* 90 00 = complete, 61 XX = more data (already fetched by send_apdu) */
    if (sw1 != 0x90 && sw1 != 0x61) {
        fprintf(stderr,
                "[yubikey-oath] CALCULATE ALL failed: %02X%02X\n", sw1, sw2);
        return;
    }

    /* First pass: count entries so we allocate exactly */
    unsigned int count = 0;
    size_t pos = 0;
    while (pos < response_len - 2) {
        TLV name_tlv, code_tlv;
        int c = parse_tlv(response + pos, response_len - 2 - pos, &name_tlv);
        if (c < 0 || name_tlv.tag != 0x71) break;
        pos += c;
        c = parse_tlv(response + pos, response_len - 2 - pos, &code_tlv);
        if (c < 0) break;
        pos += c;
        count++;
    }
    if (count == 0) return;

    pd->entries     = g_malloc0(count * sizeof(OATHEntry));
    pd->display     = g_malloc0(count * sizeof(char *));
    pd->entry_count = 0;

    /* Second pass: fill entries (name + touch flag only, no codes) */
    pos = 0;
    while (pos < response_len - 2 && pd->entry_count < count) {
        TLV name_tlv, code_tlv;
        int c = parse_tlv(response + pos, response_len - 2 - pos, &name_tlv);
        if (c < 0 || name_tlv.tag != 0x71) break;
        pos += c;
        c = parse_tlv(response + pos, response_len - 2 - pos, &code_tlv);
        if (c < 0) break;
        pos += c;

        OATHEntry *e = &pd->entries[pd->entry_count];

        /* Copy raw credential name (NUL-terminated) */
        size_t nlen = name_tlv.length < ENTRY_NAME_MAX - 1
                      ? name_tlv.length : ENTRY_NAME_MAX - 1;
        memcpy(e->name, name_tlv.value, nlen);
        e->name[nlen] = '\0';

        /*
         * tag 0x76 → card would compute directly (no touch needed)
         * tag 0x77 → HOTP or touch-required
         * tag 0x7C → touch-only TOTP
         * anything else → treat as touch-required to be safe
         */
        e->needs_touch = (code_tlv.tag != 0x76);

        pd->display[pd->entry_count] = build_display(e->name, e->needs_touch);
        pd->entry_count++;
    }
}

/**
 * Calculate TOTP for a single credential by name.
 * Used when the user selects a touch-required entry.
 * Returns a g_malloc'd string the caller must g_free(), or NULL on error.
 */
static char *
calculate_single_totp(YKOATHPrivateData *pd, const char *credential_name)
{
    unsigned char apdu[256];
    unsigned char response[256];
    size_t response_len = sizeof(response);

    uint64_t timestamp = (uint64_t)time(NULL) / 30;
    unsigned char challenge[8];
    for (int i = 7; i >= 0; i--) {
        challenge[i] = timestamp & 0xFF;
        timestamp >>= 8;
    }

    size_t name_len = strlen(credential_name);
    size_t apdu_len = 0;

    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = INS_CALCULATE;
    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = 0x01;             /* request full (truncated) response */
    apdu[apdu_len++] = 0;               /* Lc placeholder                     */
    apdu[apdu_len++] = 0x71;            /* Name tag                           */
    apdu[apdu_len++] = (unsigned char)name_len;
    memcpy(apdu + apdu_len, credential_name, name_len);
    apdu_len += name_len;
    apdu[apdu_len++] = 0x74;            /* Challenge tag */
    apdu[apdu_len++] = 8;
    memcpy(apdu + apdu_len, challenge, 8);
    apdu_len += 8;
    apdu[4] = (unsigned char)(apdu_len - 5);  /* fill in Lc */

    if (send_apdu(pd->card, pd->protocol, apdu, apdu_len,
                  response, &response_len) != 0)
        return NULL;

    if (response_len < 2 ||
        response[response_len - 2] != 0x90 ||
        response[response_len - 1] != 0x00) {
        fprintf(stderr,
                "[yubikey-oath] CALCULATE failed for '%s': %02X%02X\n",
                credential_name,
                response[response_len - 2], response[response_len - 1]);
        return NULL;
    }

    size_t pos = 0;
    while (pos < response_len - 2) {
        TLV tlv;
        int consumed = parse_tlv(response + pos, response_len - 2 - pos, &tlv);
        if (consumed < 0) break;
        if (tlv.tag == 0x76 && tlv.length >= 5) {
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
            return g_strdup_printf("%0*u", digits, code);
        }
        pos += consumed;
    }
    return NULL;
}

/* ── Clipboard helper ───────────────────────────────────────────────────── */

static void
copy_to_clipboard(const char *text)
{
    FILE *pipe = popen("wl-copy", "w");
    if (pipe) {
        fprintf(pipe, "%s", text);
        pclose(pipe);
    }
}

/* ── PC/SC initialisation / teardown ───────────────────────────────────── */

static int
pcsc_init(YKOATHPrivateData *pd)
{
    LONG rv;

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pd->context);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "[yubikey-oath] SCardEstablishContext: %s\n",
                pcsc_stringify_error(rv));
        return -1;
    }

    DWORD readers_len = 0;
    rv = SCardListReaders(pd->context, NULL, NULL, &readers_len);
    if (rv != SCARD_S_SUCCESS || readers_len == 0) {
        fprintf(stderr, "[yubikey-oath] SCardListReaders (size): %s\n",
                pcsc_stringify_error(rv));
        SCardReleaseContext(pd->context);
        return -1;
    }

    pd->readers = g_malloc(readers_len);
    rv = SCardListReaders(pd->context, NULL, pd->readers, &readers_len);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "[yubikey-oath] SCardListReaders: %s\n",
                pcsc_stringify_error(rv));
        g_free(pd->readers);
        pd->readers = NULL;
        SCardReleaseContext(pd->context);
        return -1;
    }

    rv = SCardConnect(pd->context, pd->readers,
                      SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                      &pd->card, &pd->protocol);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "[yubikey-oath] SCardConnect: %s\n",
                pcsc_stringify_error(rv));
        g_free(pd->readers);
        pd->readers = NULL;
        SCardReleaseContext(pd->context);
        return -1;
    }

    if (select_oath_app(pd->card, pd->protocol) != 0) {
        fprintf(stderr, "[yubikey-oath] Failed to select OATH application\n");
        SCardDisconnect(pd->card, SCARD_LEAVE_CARD);
        g_free(pd->readers);
        pd->readers = NULL;
        SCardReleaseContext(pd->context);
        return -1;
    }

    return 0;
}

static void
pcsc_teardown(YKOATHPrivateData *pd)
{
    if (pd->pcsc_ok) {
        SCardDisconnect(pd->card, SCARD_LEAVE_CARD);
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

    YKOATHPrivateData *pd = g_malloc0(sizeof(*pd));
    mode_set_private_data(sw, pd);

    if (pcsc_init(pd) == 0) {
        pd->pcsc_ok = 1;
        load_entries(pd);
    } else {
        pd->pcsc_ok = 0;
        /* Show a single error entry so the user sees something */
        pd->entries     = g_malloc0(sizeof(OATHEntry));
        pd->display     = g_malloc0(sizeof(char *));
        pd->entry_count = 1;
        strncpy(pd->entries[0].name, "Error: YubiKey not found",
                ENTRY_NAME_MAX - 1);
        pd->entries[0].needs_touch = 0;
        pd->display[0] = g_strdup("Error: YubiKey not found");
    }

    return TRUE;
}

static unsigned int
myplugin_mode_get_num_entries(const Mode *sw)
{
    const YKOATHPrivateData *pd =
        (const YKOATHPrivateData *)mode_get_private_data(sw);
    return pd->entry_count;
}

static ModeMode
myplugin_mode_result(Mode *sw, int mretv,
                     G_GNUC_UNUSED char **input,
                     unsigned int selected_line)
{
    YKOATHPrivateData *pd = (YKOATHPrivateData *)mode_get_private_data(sw);

    if (mretv & MENU_NEXT)         return NEXT_DIALOG;
    if (mretv & MENU_PREVIOUS)     return PREVIOUS_DIALOG;
    if (mretv & MENU_QUICK_SWITCH) return (ModeMode)(mretv & MENU_LOWER_MASK);

    if ((mretv & MENU_OK) && pd->pcsc_ok &&
        selected_line < pd->entry_count) {
        OATHEntry *e = &pd->entries[selected_line];

        /*
         * Always request a fresh code — we never cache them in the list.
         * Re-select the OATH app first in case the card session has idled.
         * For touch-required credentials the key will block until touched.
         */
        select_oath_app(pd->card, pd->protocol);
        char *code = calculate_single_totp(pd, e->name);
        if (code) {
            copy_to_clipboard(code);
            g_free(code);
        }
        return MODE_EXIT;
    }

    if (mretv & MENU_ENTRY_DELETE)
        return RELOAD_DIALOG;

    return MODE_EXIT;
}

static void
myplugin_mode_destroy(Mode *sw)
{
    YKOATHPrivateData *pd = (YKOATHPrivateData *)mode_get_private_data(sw);
    if (pd == NULL) return;

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

    if (!get_entry) return NULL;
    if (selected_line >= pd->entry_count) return g_strdup("n/a");
    return g_strdup(pd->display[selected_line]);
}

static int
myplugin_token_match(const Mode *sw, rofi_int_matcher **tokens,
                     unsigned int index)
{
    const YKOATHPrivateData *pd =
        (const YKOATHPrivateData *)mode_get_private_data(sw);

    if (index >= pd->entry_count) return 0;
    /*
     * Match against the raw credential name (e.g. "GitHub:alice"), not the
     * Pango-markup display string — otherwise "<i>" would appear in searches.
     */
    return helper_token_match(tokens, pd->entries[index].name);
}

/* ── Mode descriptor ────────────────────────────────────────────────────── */

Mode mode = {
    .abi_version        = ABI_VERSION,
    .name               = "yubikey-oath",
    .cfg_name_key       = "display-yubikey-oath",
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
