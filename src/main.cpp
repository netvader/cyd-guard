// ============================================================================
//  CYD GUARD
//  WiFi Deauth Detector + BLE Jam Detector for the Sunton ESP32-2432S024R
//  (2.4" ILI9341 240x320, resistive XPT2046 touch)
//
//  IMPORTANT: Both features are purely PASSIVE (receive/listen only).
//  Nothing is ever transmitted or jammed by this device.
//
//  WiFi part: puts the WiFi radio into promiscuous mode, listens to all
//             management frames and filters Deauthentication (subtype 0x0C)
//             and Disassociation (subtype 0x0A) frames.
//  BLE part:  counts incoming BLE advertisements per second and learns a
//             rolling baseline. A sudden, sustained drop in that rate is a
//             typical symptom of RF jamming and triggers an alert.
//             => This is a heuristic, not a real spectrum analysis!
// ============================================================================

#include <Arduino.h>
#include <math.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <NimBLEDevice.h>

// ---------------------------------------------------------------------------
// Touch calibration (TFT_eSPI's built-in touch, shares the SPI bus with the
// display - TOUCH_CS=33 is already set in platformio.ini).
// Set RUN_TOUCH_CALIBRATION to true once, flash, follow the on-screen
// instructions, copy the 5 values printed on the serial monitor (115200
// baud) into calData[] below, then set it back to false and reflash.
// ---------------------------------------------------------------------------
#define RUN_TOUCH_CALIBRATION false
uint16_t calData[5] = { 609, 3009, 377, 3355, 3 };

TFT_eSPI tft = TFT_eSPI();

// ---------------------------------------------------------------------------
// Screen geometry - portrait layout (240x320)
// ---------------------------------------------------------------------------
#define SCREEN_W 240
#define SCREEN_H 320
#define HEADER_H 26
#define TABBAR_H 34
#define CONTENT_Y (HEADER_H)
#define CONTENT_H (SCREEN_H - HEADER_H - TABBAR_H)

// ---------------------------------------------------------------------------
// Colors - 80s synthwave / outrun neon palette
// ---------------------------------------------------------------------------
uint16_t COL_BG, COL_CARD, COL_CARD_BORDER, COL_ACCENT, COL_GOOD, COL_WARN,
         COL_BAD, COL_TEXT, COL_DIM;

void initColors() {
  COL_BG          = tft.color565(0, 0, 0);      // pure black
  COL_CARD        = tft.color565(10, 6, 16);    // near-black panel, just enough to see the edge
  COL_CARD_BORDER = tft.color565(255, 0, 255);  // full neon magenta
  COL_ACCENT      = tft.color565(0, 255, 255);  // full neon cyan
  COL_GOOD        = tft.color565(40, 255, 90);  // neon green
  COL_WARN        = tft.color565(255, 190, 0);  // full neon amber
  COL_BAD         = tft.color565(255, 30, 30);  // neon red, matches the external status LED
  COL_TEXT        = tft.color565(255, 255, 255);
  COL_DIM         = tft.color565(180, 140, 210);
}

void drawSunsetBackground(int y0, int y1) {
  // Pure black backdrop - the neon UI elements provide all the color.
  tft.fillRect(0, y0, SCREEN_W, y1 - y0, COL_BG);
}

// ---------------------------------------------------------------------------
// General state
// ---------------------------------------------------------------------------
enum Screen { SCR_WIFI, SCR_BLE };
Screen currentScreen = SCR_WIFI;
Screen lastDrawnScreen = SCR_BLE; // force initial full draw
bool alertBlinkOn = false;
uint32_t lastBlinkMs = 0;
uint32_t lastUiTick = 0;

// ---------------------------------------------------------------------------
// WiFi Deauth Detector state
// ---------------------------------------------------------------------------
struct DeauthEvent {
  uint32_t t;
  uint8_t src[6];
  uint8_t dst[6];
  uint8_t channel;
  int8_t rssi;
  bool broadcast;
  bool isDisassoc;
};

#define LOG_SIZE 5
DeauthEvent logBuf[LOG_SIZE];
uint8_t logHead = 0;
uint8_t logCount = 0;

volatile uint32_t deauthTotal = 0;
volatile uint32_t deauthWindowCount = 0; // incremented in ISR, drained once/sec

uint8_t currentChannel = 1;
uint32_t lastChannelHop = 0;
const uint32_t CHANNEL_HOP_MS = 400;

bool wifiAlert = false;
uint32_t lastDeauthMs = 0;
const uint32_t ALERT_HOLD_MS = 8000; // alert stays active for 8s after the last event

void macToStr(const uint8_t *mac, char *out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *payload = pkt->payload;

  uint16_t fctl = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
  uint8_t ftype = (fctl >> 2) & 0x03;
  uint8_t fsubtype = (fctl >> 4) & 0x0F;

  if (ftype != 0) return; // management frames only
  bool isDeauth = (fsubtype == 0x0C);
  bool isDisassoc = (fsubtype == 0x0A);
  if (!isDeauth && !isDisassoc) return;

  DeauthEvent ev;
  ev.t = millis();
  memcpy(ev.dst, payload + 4, 6);
  memcpy(ev.src, payload + 10, 6);
  ev.channel = pkt->rx_ctrl.channel;
  ev.rssi = pkt->rx_ctrl.rssi;
  ev.isDisassoc = isDisassoc;
  ev.broadcast = (ev.dst[0] == 0xFF && ev.dst[1] == 0xFF && ev.dst[2] == 0xFF &&
                  ev.dst[3] == 0xFF && ev.dst[4] == 0xFF && ev.dst[5] == 0xFF);

  logBuf[logHead] = ev;
  logHead = (logHead + 1) % LOG_SIZE;
  if (logCount < LOG_SIZE) logCount++;

  deauthTotal++;
  deauthWindowCount++;
}

void startWifiSniffer() {
  WiFi.disconnect(true);
  WiFi.mode(WIFI_MODE_STA);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

// ---------------------------------------------------------------------------
// BLE Jam Detector state
// ---------------------------------------------------------------------------
volatile uint32_t bleAdvCountWindow = 0;

#define BLE_HIST_SIZE 40
uint16_t bleHistory[BLE_HIST_SIZE] = {0};
uint8_t bleHistIdx = 0;

bool bleBaselineReady = false;
uint32_t warmupSum = 0;
uint8_t warmupN = 0;
float bleBaseline = 0;
uint8_t bleLowStreak = 0;
bool bleAlert = false;
uint32_t lastBleAlertMs = 0;
uint16_t lastBleCount = 0;

class AdvCallbacks : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice *dev) override {
    bleAdvCountWindow++;
  }
};
AdvCallbacks advCallbacks;

void startBleScanner() {
  NimBLEDevice::init("");
  NimBLEScan *pScan = NimBLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(&advCallbacks, true /* allow duplicates -> count rate */);
  pScan->setActiveScan(false); // passive scanning is enough for counting, saves airtime
  pScan->setInterval(100);
  pScan->setWindow(90);
  pScan->start(0, nullptr, false); // 0 = forever, non-blocking
}

void bleTick(uint16_t count) {
  lastBleCount = count;
  bleHistory[bleHistIdx] = count;
  bleHistIdx = (bleHistIdx + 1) % BLE_HIST_SIZE;

  if (!bleBaselineReady) {
    warmupSum += count;
    warmupN++;
    if (warmupN >= 8) {
      bleBaseline = warmupSum / (float)warmupN;
      if (bleBaseline < 1.0) bleBaseline = 1.0;
      bleBaselineReady = true;
    }
    return;
  }

  bool lowActivity = (count < bleBaseline * 0.3) && (bleBaseline > 3.0);
  if (lowActivity) {
    if (bleLowStreak < 255) bleLowStreak++;
  } else {
    bleLowStreak = 0;
    bleBaseline = bleBaseline * 0.85f + count * 0.15f; // only adapt baseline while activity looks normal
  }

  if (bleLowStreak >= 3) {
    bleAlert = true;
    lastBleAlertMs = millis();
  }
  if (bleAlert && millis() - lastBleAlertMs > ALERT_HOLD_MS) {
    bleAlert = false;
  }
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------
void drawCard(int x, int y, int w, int h, const char *title) {
  tft.fillRoundRect(x, y, w, h, 6, COL_CARD);
  tft.drawRoundRect(x, y, w, h, 6, COL_CARD_BORDER);
  if (title) {
    tft.setTextColor(COL_DIM, COL_CARD);
    tft.setTextFont(1);
    tft.setTextSize(1);
    tft.setCursor(x + 8, y + 6);
    tft.print(title);
  }
}

void drawHeaderStatic(const char *title) {
  tft.fillRect(0, 0, SCREEN_W, HEADER_H, COL_BG);

  // Neon sunset gradient underline (magenta -> orange -> cyan)
  for (int x = 0; x < SCREEN_W; x++) {
    float t = (float)x / (SCREEN_W - 1);
    uint8_t r, g, b;
    if (t < 0.5f) {
      float u = t / 0.5f;
      r = 255; g = (uint8_t)(20 + 150 * u); b = (uint8_t)(150 - 110 * u);
    } else {
      float u = (t - 0.5f) / 0.5f;
      r = (uint8_t)(255 - 255 * u); g = (uint8_t)(170 - 20 * u); b = (uint8_t)(40 + 215 * u);
    }
    tft.drawPixel(x, HEADER_H - 2, tft.color565(r, g, b));
    tft.drawPixel(x, HEADER_H - 1, tft.color565(r, g, b));
  }

  // Small retro "sunset" icon: a striped circle, like the classic outrun sun logo
  int sunX = 15, sunY = HEADER_H / 2 - 1;
  tft.fillCircle(sunX, sunY, 8, tft.color565(255, 130, 40));
  tft.drawFastHLine(sunX - 8, sunY - 2, 16, COL_BG);
  tft.drawFastHLine(sunX - 8, sunY + 1, 16, COL_BG);
  tft.drawFastHLine(sunX - 8, sunY + 4, 16, COL_BG);

  tft.setTextColor(COL_ACCENT, COL_BG);
  tft.setTextFont(2);
  tft.setCursor(30, 4);
  tft.print(title);
}

void updateHeaderClock() {
  // Only redraw the small clock area instead of the whole header, otherwise
  // it visibly flashes on every UI tick (clear+redraw 4x/sec).
  static char lastBuf[16] = "";
  char buf[16];
  uint32_t s = millis() / 1000;
  sprintf(buf, "%02u:%02u:%02u", (unsigned)(s / 3600), (unsigned)((s / 60) % 60), (unsigned)(s % 60));
  if (strcmp(buf, lastBuf) == 0) return;
  strcpy(lastBuf, buf);

  tft.setTextFont(1);
  int tw = tft.textWidth(buf);
  tft.fillRect(SCREEN_W - 60, 0, 60, HEADER_H - 1, COL_BG);
  tft.setTextColor(COL_DIM, COL_BG);
  tft.setCursor(SCREEN_W - tw - 6, 9);
  tft.print(buf);
}

void drawTabBar() {
  int y = SCREEN_H - TABBAR_H;
  tft.fillRect(0, y, SCREEN_W, TABBAR_H, COL_BG);

  int w = SCREEN_W / 2;
  for (int i = 0; i < 2; i++) {
    bool active = (i == 0 && currentScreen == SCR_WIFI) || (i == 1 && currentScreen == SCR_BLE);
    uint16_t bg = active ? COL_ACCENT : COL_CARD;
    uint16_t fg = active ? COL_BG : COL_DIM;
    tft.fillRoundRect(i * w + 4, y + 4, w - 8, TABBAR_H - 8, 6, bg);
    tft.setTextColor(fg, bg);
    tft.setTextFont(2);
    const char *label = (i == 0) ? "WIFI DEAUTH" : "BLE JAM";
    int tw = tft.textWidth(label);
    tft.setCursor(i * w + w / 2 - tw / 2, y + 9);
    tft.print(label);
  }
}

void handleTouch() {
  uint16_t x, y;
  if (!tft.getTouch(&x, &y)) return;
  if (y < SCREEN_H - TABBAR_H) return; // only the tab bar is interactive
  static uint32_t lastTouchMs = 0;
  if (millis() - lastTouchMs < 300) return; // debounce
  lastTouchMs = millis();

  Screen newScreen = (x < SCREEN_W / 2) ? SCR_WIFI : SCR_BLE;
  if (newScreen != currentScreen) {
    currentScreen = newScreen;
  }
}

// ---------------------------------------------------------------------------
// WiFi screen
// ---------------------------------------------------------------------------
void drawWifiScreenStatic() {
  drawSunsetBackground(CONTENT_Y, SCREEN_H - TABBAR_H);
  drawHeaderStatic("WiFi Deauth Detector");
  drawCard(6, CONTENT_Y + 4, 228, 44, "STATUS");
  drawCard(6, CONTENT_Y + 52, 110, 44, "TOTAL");
  drawCard(122, CONTENT_Y + 52, 112, 44, "CHANNEL");
  drawCard(6, CONTENT_Y + 100, 228, CONTENT_H - 104, "RECENT EVENTS");
}

void updateWifiStatusFast() {
  // Status card, counter, channel - cheap, safe to redraw often
  bool alertNow = wifiAlert && (millis() - lastDeauthMs < ALERT_HOLD_MS);
  uint16_t statCol = alertNow ? (alertBlinkOn ? COL_BAD : tft.color565(100, 15, 15)) : COL_GOOD;
  tft.fillRoundRect(14, CONTENT_Y + 22, 20, 20, 4, statCol);
  tft.setTextColor(alertNow ? COL_BAD : COL_GOOD, COL_CARD);
  tft.setTextFont(2);
  tft.fillRect(40, CONTENT_Y + 22, 180, 20, COL_CARD);
  tft.setCursor(40, CONTENT_Y + 25);
  tft.print(alertNow ? "ATTACK DETECTED!" : "SAFE");

  // Total counter
  tft.setTextColor(COL_TEXT, COL_CARD);
  tft.setTextFont(2);
  char buf[16];
  sprintf(buf, "%lu", (unsigned long)deauthTotal);
  tft.fillRect(14, CONTENT_Y + 72, 96, 22, COL_CARD);
  tft.setCursor(14, CONTENT_Y + 76);
  tft.print(buf);

  // Channel
  sprintf(buf, "%d", currentChannel);
  tft.fillRect(130, CONTENT_Y + 72, 96, 22, COL_CARD);
  tft.setCursor(130, CONTENT_Y + 76);
  tft.print(buf);
}

void updateWifiLog() {
  // Event list only changes on a new event or once per second (time display),
  // so it must NOT be redrawn on every 250ms UI tick (would visibly flash).
  int logY = CONTENT_Y + 122;
  int rowH = (CONTENT_H - 126) / LOG_SIZE;
  tft.fillRect(10, logY, 220, rowH * LOG_SIZE, COL_CARD);
  if (logCount == 0) {
    tft.setTextColor(COL_DIM, COL_CARD);
    tft.setTextFont(2);
    tft.setCursor(14, logY + 6);
    tft.print("No events detected yet.");
  } else {
    for (uint8_t i = 0; i < logCount; i++) {
      int idx = (logHead - 1 - i + LOG_SIZE * 2) % LOG_SIZE;
      DeauthEvent &ev = logBuf[idx];
      uint32_t ago = (millis() - ev.t) / 1000;
      char line[48];
      sprintf(line, "%s %02X:%02X ch%d %lds", ev.isDisassoc ? "DISASSOC" : "DEAUTH",
              ev.src[4], ev.src[5], ev.channel, (unsigned long)ago);
      tft.setTextColor(ev.broadcast ? COL_BAD : COL_WARN, COL_CARD);
      tft.setTextFont(1);
      tft.setCursor(14, logY + i * rowH + 4);
      tft.print(line);
    }
  }
}

// ---------------------------------------------------------------------------
// BLE screen
// ---------------------------------------------------------------------------
void drawBleScreenStatic() {
  drawSunsetBackground(CONTENT_Y, SCREEN_H - TABBAR_H);
  drawHeaderStatic("BLE Jam Detector");
  drawCard(6, CONTENT_Y + 4, 228, 44, "STATUS");
  drawCard(6, CONTENT_Y + 52, 110, 44, "RATE/BASE");
  drawCard(122, CONTENT_Y + 52, 112, 44, "STREAK");
  drawCard(6, CONTENT_Y + 100, 228, CONTENT_H - 104, "ADV/S HISTORY");
}

void updateBleStatusFast() {
  bool alertNow = bleAlert;
  uint16_t statCol = alertNow ? (alertBlinkOn ? COL_BAD : tft.color565(100, 15, 15)) : COL_GOOD;
  tft.fillRoundRect(14, CONTENT_Y + 22, 20, 20, 4, statCol);
  tft.fillRect(40, CONTENT_Y + 22, 180, 20, COL_CARD);
  tft.setTextColor(alertNow ? COL_BAD : COL_GOOD, COL_CARD);
  tft.setTextFont(2);
  tft.setCursor(40, CONTENT_Y + 25);
  tft.print(alertNow ? "POSSIBLE JAMMING" : "OK");

  char buf[24];
  sprintf(buf, "%u/%d", lastBleCount, (int)bleBaseline);
  tft.fillRect(14, CONTENT_Y + 74, 96, 20, COL_CARD);
  tft.setTextColor(COL_TEXT, COL_CARD);
  tft.setTextFont(2);
  tft.setCursor(14, CONTENT_Y + 74);
  tft.print(buf);

  sprintf(buf, "%d/3", bleLowStreak > 3 ? 3 : bleLowStreak);
  tft.fillRect(130, CONTENT_Y + 74, 96, 20, COL_CARD);
  tft.setCursor(130, CONTENT_Y + 74);
  tft.print(buf);
}

void updateBleGraph() {
  // Bar chart data only changes once per second (bleTick), so only redraw it
  // once per second too, not on every 250ms UI tick (would visibly flash).
  int gx = 10, gy = CONTENT_Y + 122, gw = 218, gh = CONTENT_H - 132;
  tft.fillRect(gx, gy, gw, gh, COL_CARD);
  uint16_t maxVal = 1;
  for (int i = 0; i < BLE_HIST_SIZE; i++) if (bleHistory[i] > maxVal) maxVal = bleHistory[i];
  for (int i = 0; i < BLE_HIST_SIZE; i++) {
    int idx = (bleHistIdx + i) % BLE_HIST_SIZE; // oldest first -> chronological left to right
    int barH = (int)((float)bleHistory[idx] / maxVal * (gh - 4));
    if (barH < 1) barH = 1;
    uint16_t c = (bleHistory[idx] < bleBaseline * 0.3 && bleBaseline > 3.0) ? COL_BAD : COL_GOOD;
    // Compute each bar's left/right edge from gw directly (not a fixed barW)
    // so the last bar reaches the full width instead of leaving a rounding gap.
    int xLeft = gx + (i * gw) / BLE_HIST_SIZE;
    int xRight = gx + ((i + 1) * gw) / BLE_HIST_SIZE;
    tft.fillRect(xLeft + 1, gy + gh - barH, xRight - xLeft - 1, barH, c);
  }
}

// ---------------------------------------------------------------------------
// External status LED. This LED is ACTIVE-LOW (confirmed against the
// reference esp32-smartdisplay library: "digitalWrite(RGB_LED_R, !r)",
// comment "High is off") and the vendor's G/B pin labels are swapped from
// reality on this unit: GPIO4 = red, GPIO17 = green, GPIO16 = blue.
// LEDC duty is inverted accordingly (0 = fully on, max = fully off).
// ---------------------------------------------------------------------------
#define LED_R 4
#define LED_G 17
#define LED_B 16
#define LED_PWM_CH_R 0
#define LED_PWM_CH_G 1
#define LED_PWM_CH_B 2
#define LED_PWM_FREQ 5000
#define LED_PWM_RES 8

void setStatusLed(bool alert) {
  if (!alert) {
    // Safe: slow breathing pulse (~2.4s period) mixing red+green for a
    // warm orange/yellow glow, now that both channels are confirmed working
    float phase = (millis() % 2400) / 2400.0f;
    float s = (sinf(phase * 2.0f * PI) + 1.0f) / 2.0f; // 0..1
    uint8_t brightness = (uint8_t)(30 + s * 225); // never fully off, stays visible
    ledcWrite(LED_PWM_CH_R, 255 - brightness); // active-low: invert duty
    ledcWrite(LED_PWM_CH_G, 255 - brightness);
    ledcWrite(LED_PWM_CH_B, 255);              // blue off
  } else {
    // Alert: steady, unmissable full-brightness red
    ledcWrite(LED_PWM_CH_R, 0);   // active-low: 0 = fully on
    ledcWrite(LED_PWM_CH_G, 255);
    ledcWrite(LED_PWM_CH_B, 255);
  }
}

// ---------------------------------------------------------------------------
// Synthwave boot logo
// ---------------------------------------------------------------------------
void drawBootLogo() {
  tft.fillScreen(TFT_BLACK);

  // Retro sun: filled circle with a top-to-bottom orange -> hot pink gradient,
  // cut by a few horizontal gap stripes like the classic outrun sun logo.
  int cx = SCREEN_W / 2, cy = 80, r = 44;
  for (int dy = -r; dy <= r; dy++) {
    int w = (int)sqrt((float)(r * r - dy * dy));
    float t = (float)(dy + r) / (2.0f * r);
    uint8_t rr = (uint8_t)(255);
    uint8_t gg = (uint8_t)(200 - 160 * t);
    uint8_t bb = (uint8_t)(50 + 100 * t);
    tft.drawFastHLine(cx - w, cy + dy, 2 * w + 1, tft.color565(rr, gg, bb));
  }
  int gapYs[3] = { -6, 10, 26 };
  for (int i = 0; i < 3; i++) {
    int dy = gapYs[i];
    int w = (int)sqrt((float)(r * r - dy * dy));
    tft.drawFastHLine(cx - w, cy + dy, 2 * w + 1, TFT_BLACK);
  }

  // Horizon: bright magenta -> orange -> cyan gradient line
  int horizonY = cy + r + 10;
  for (int x = 0; x < SCREEN_W; x++) {
    float t = (float)x / (SCREEN_W - 1);
    uint8_t r2, g2, b2;
    if (t < 0.5f) {
      float u = t / 0.5f;
      r2 = 255; g2 = (uint8_t)(20 + 150 * u); b2 = (uint8_t)(150 - 110 * u);
    } else {
      float u = (t - 0.5f) / 0.5f;
      r2 = (uint8_t)(255 - 255 * u); g2 = (uint8_t)(170 - 20 * u); b2 = (uint8_t)(40 + 215 * u);
    }
    tft.drawPixel(x, horizonY, tft.color565(r2, g2, b2));
    tft.drawPixel(x, horizonY + 1, tft.color565(r2, g2, b2));
  }

  // Perspective grid floor: horizontal lines closer together near the
  // horizon, plus lines radiating from the vanishing point.
  int gridBottom = SCREEN_H;
  int vpX = cx, vpY = horizonY;
  for (int i = 1; i <= 7; i++) {
    float t = (float)i / 7.0f;
    int y = horizonY + (int)((gridBottom - horizonY) * t * t); // eased spacing
    uint16_t c = tft.color565(60 + 40 * t, 10, 90 + 60 * t);
    tft.drawFastHLine(0, y, SCREEN_W, c);
  }
  int fanXs[9] = { -120, -80, -50, -20, 0, 20, 50, 80, 120 };
  for (int i = 0; i < 9; i++) {
    int x2 = vpX + fanXs[i] * 2;
    tft.drawLine(vpX, vpY, x2, gridBottom, tft.color565(90, 20, 130));
  }

  // Title with a chromatic-aberration style neon glow: magenta shadow offset
  // behind a cyan main pass.
  const char *title = "CYD GUARD";
  tft.setTextFont(4);
  int tw = tft.textWidth(title);
  int tx = (SCREEN_W - tw) / 2;
  int ty = 200;
  tft.setTextColor(tft.color565(255, 0, 220), TFT_BLACK);
  tft.setCursor(tx - 2, ty + 2);
  tft.print(title);
  tft.setTextColor(tft.color565(0, 255, 255), TFT_BLACK);
  tft.setCursor(tx, ty);
  tft.print(title);

  const char *subtitle = "WIFI DEAUTH + BLE JAM DETECTOR";
  tft.setTextFont(1);
  int stw = tft.textWidth(subtitle);
  tft.setTextColor(tft.color565(180, 140, 210), TFT_BLACK);
  tft.setCursor((SCREEN_W - stw) / 2, ty + 34);
  tft.print(subtitle);

  delay(2500);
}

// ---------------------------------------------------------------------------
// Setup / loop
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);

  // The SD card CS shares the display's SPI bus - deselect it explicitly,
  // otherwise it can interfere with display communication.
  pinMode(5, OUTPUT);
  digitalWrite(5, HIGH);

  tft.init();
  tft.setRotation(0); // 240x320 portrait
  tft.fillScreen(TFT_BLACK);

  if (RUN_TOUCH_CALIBRATION) {
    tft.setCursor(10, 10);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.println("Touch calibration:");
    tft.println("Touch the corners as shown.");
    tft.calibrateTouch(calData, TFT_MAGENTA, TFT_BLACK, 15);
    Serial.println("Calibration values - copy into calData[] in the code:");
    Serial.printf("{ %d, %d, %d, %d, %d };\n", calData[0], calData[1], calData[2], calData[3], calData[4]);
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(10, 10);
    tft.println("Values printed on serial monitor.");
    tft.println("Set RUN_TOUCH_CALIBRATION to");
    tft.println("false and reflash.");
    while (true) delay(1000);
  }
  tft.setTouch(calData);

  initColors();
  drawBootLogo();

  startWifiSniffer();
  Serial.println("[CYD Guard] WiFi promiscuous sniffer started.");
  startBleScanner();
  Serial.println("[CYD Guard] BLE scanner started.");

  ledcSetup(LED_PWM_CH_R, LED_PWM_FREQ, LED_PWM_RES);
  ledcAttachPin(LED_R, LED_PWM_CH_R);
  ledcSetup(LED_PWM_CH_G, LED_PWM_FREQ, LED_PWM_RES);
  ledcAttachPin(LED_G, LED_PWM_CH_G);
  ledcSetup(LED_PWM_CH_B, LED_PWM_FREQ, LED_PWM_RES);
  ledcAttachPin(LED_B, LED_PWM_CH_B);
  setStatusLed(false);

  delay(300);
  tft.fillScreen(COL_BG);
}

void loop() {
  uint32_t now = millis();

  // Poll touch
  handleTouch();

  // WiFi channel hopping
  if (now - lastChannelHop > CHANNEL_HOP_MS) {
    lastChannelHop = now;
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }

  // Once per second: evaluate deauth rate + BLE tick
  static uint32_t lastSecTick = 0;
  if (now - lastSecTick >= 1000) {
    lastSecTick = now;

    uint32_t dCount = deauthWindowCount;
    deauthWindowCount = 0;
    if (dCount > 0) {
      wifiAlert = true;
      lastDeauthMs = now;
    }
    if (wifiAlert && now - lastDeauthMs > ALERT_HOLD_MS) wifiAlert = false;

    uint32_t bCount = bleAdvCountWindow;
    bleAdvCountWindow = 0;
    bleTick((uint16_t)bCount);

    // The event list / bar chart only change here (once/sec) -> only redraw
    // them here, independent of the 250ms UI tick (prevents flashing).
    if (currentScreen == SCR_WIFI) updateWifiLog();
    else updateBleGraph();

    Serial.printf("[%lus] deauth=%lu (total=%lu) ble_adv=%u baseline=%.1f alert_wifi=%d alert_ble=%d\n",
                  (unsigned long)(now / 1000), (unsigned long)dCount, (unsigned long)deauthTotal,
                  (unsigned)bCount, bleBaseline, wifiAlert, bleAlert);
  }

  // Blink rate for the alert indicator
  if (now - lastBlinkMs > 500) {
    lastBlinkMs = now;
    alertBlinkOn = !alertBlinkOn;
  }

  // Refresh the UI about 4x per second (only the cheap, frequently changing parts)
  if (now - lastUiTick > 250) {
    lastUiTick = now;
    if (currentScreen != lastDrawnScreen) {
      tft.fillScreen(COL_BG);
      if (currentScreen == SCR_WIFI) { drawWifiScreenStatic(); updateWifiLog(); }
      else { drawBleScreenStatic(); updateBleGraph(); }
      lastDrawnScreen = currentScreen;
      drawTabBar();
    }
    updateHeaderClock();
    if (currentScreen == SCR_WIFI) updateWifiStatusFast();
    else updateBleStatusFast();

    // Re-evaluate the LED every UI tick (not just once/sec) so it updates
    // immediately, including right when switching between the two tabs.
    setStatusLed(wifiAlert || bleAlert);
  }
}
