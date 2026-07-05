# CYD Guard

A passive WiFi deauthentication detector and BLE jamming heuristic for the
Sunton **ESP32-2432S024R** ("Cheap Yellow Display" style board, 2.4" ILI9341
touchscreen), with a synthwave-themed touch UI and a tri-color status LED.

Built with [Claude Code](https://claude.com/claude-code).

Both detectors are purely **passive** (receive/listen only) — nothing is
ever transmitted or jammed by this firmware.

## Features

- **WiFi tab**: puts the WiFi radio into promiscuous mode and hops through
  channels 1–13. Detects Deauthentication and Disassociation management
  frames, shows a live counter, current channel, and an event log with
  source MAC. Broadcast deauth (targeting `FF:FF:FF:FF:FF:FF`, i.e. every
  client at once) is highlighted.
- **BLE tab**: counts incoming BLE advertisements per second and learns a
  rolling baseline. If the rate drops below ~30% of that baseline for 3
  consecutive seconds, it raises an alert — a typical symptom of RF jamming
  in the 2.4 GHz band. **This is a heuristic, not real spectrum analysis**
  and can produce false positives (e.g. nearby BLE devices being turned off).
- Portrait 240×320 UI with a synthwave boot logo, neon color palette, and a
  tri-color status LED that pulses orange while safe and turns solid red
  during an alert.

## Hardware notes

This board ships with several undocumented quirks that this firmware works
around — worth knowing if you build for a different unit of the same family:

- **Backlight**: GPIO 27 (not the commonly-documented GPIO 21).
- **Touch**: shares the display's SPI bus (XPT2046 via TFT_eSPI's built-in
  touch support), CS on GPIO 33.
- **Status LED**: active-LOW, and the vendor's pin labels don't match
  reality on this unit — GPIO 4 = red, GPIO 17 = green, GPIO 16 = blue
  (vendor docs claim R=4, G=16, B=17).
- **SD card CS** (GPIO 5) shares the display's SPI bus and must be
  explicitly deselected at boot, or it can interfere with the display.

## Building and flashing

```bash
pio run -t upload
pio device monitor -b 115200
```

### Touch calibration

Set `RUN_TOUCH_CALIBRATION` to `true` in `src/main.cpp`, flash, follow the
on-screen prompts, then copy the 5 values printed on the serial monitor into
`calData[]`. Set the flag back to `false` and reflash.

## Legal

Both detectors are receive-only and legal to operate in most jurisdictions
(check your local telecom regulations). An active jammer was intentionally
**not** implemented — radio jammers are illegal in most countries (e.g. in
Germany under §55 TKG, with fines up to €100,000).

## License

MIT — see [LICENSE](LICENSE).
