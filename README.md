# rofi-yubikey-oath

A [rofi](https://github.com/davatorium/rofi) plugin that lists the OATH TOTP
credentials stored on a YubiKey and copies the selected one-time code to the
Wayland clipboard via `wl-copy`.

## How it works

1. On startup the plugin opens a PC/SC session, connects to the first
   smart-card reader it finds, and issues a `CALCULATE ALL` APDU to the
   YubiKey's OATH application.
2. All credentials are listed in rofi. Credentials that require a physical
   touch are shown with a leading 🔒.
3. Selecting an entry copies the code to the clipboard and closes rofi. For
   touch-required entries the plugin issues a targeted `CALCULATE` APDU —
   touch the key when prompted and the code is then copied automatically.


## Dependencies

```sh
# Alpine Linux
sudo apk add meson rofi-dev glib-dev pcsclite-dev ccid wl-clipboard
sudo rc-update add pcscd default

# Debian / Ubuntu (untested)
sudo apt install meson rofi-dev libglib2.0-dev libpcsclite-dev wl-clipboard pcscd
```

Make sure pcscd is running and you have the rights:

```sh
service pcscd status
sudo usermod -a -G plugdev,pcscd $USER
```

## Build & install

```sh
meson setup build/
#meson compile -C build/
sudo meson install -C build/
```

## Usage

```sh
rofi -modi yubikey-oath -show yubikey-oath
```

Bind it to a key in your compositor, e.g. for Sway:

```
bindsym $mod+y exec rofi -modi yubikey-oath -show yubikey-oath
```

## Notes

- Only the **first** PC/SC reader is used. If you have multiple readers,
  the YubiKey must be the first one enumerated by `pcscd`.
- HOTP credentials are treated as touch-required (tag `0x77`).
- The plugin keeps the PC/SC connection open for the duration of the rofi
  session and closes it cleanly on exit.
- For X11 sessions compatibility, one could substitute `wl-copy` for
`xclip -selection clipboard` by editing `copy_to_clipboard()`.
