# CYD Guard

WiFi-Deauth-Detector + BLE-Jam-Detector für das CYD (ESP32-2432S024).
Beide Funktionen sind rein passiv (Empfangen/Mitlesen) – es wird nicht gesendet.

## Build-Status

Erfolgreich mit PlatformIO kompiliert (Flash 79.8%, RAM 16.5% belegt).
Getestet wurde nur der Compile-Vorgang, nicht auf echter Hardware.

## Flashen

```bash
pio run -t upload
pio device monitor -b 115200
```

## Vor dem ersten Betrieb prüfen

- **Panel-Treiber**: Standard ist `ILI9341_2_DRIVER`. Falls Farben falsch/invertiert
  sind, in `platformio.ini` auf `ST7789_DRIVER` umstellen.
- **Touch-Kalibrierung**: `DEBUG_TOUCH` in `src/main.cpp` auf `true` setzen, die vier
  Ecken berühren, Rohwerte im seriellen Monitor ablesen und `TS_MINX/MAXX/MINY/MAXY`
  entsprechend anpassen. Danach wieder auf `false`.

## Funktionsweise

- **WiFi-Tab**: WiFi-Chip läuft im Promiscuous-Mode und hoppt durch Kanal 1–13.
  Erkennt Deauthentication- und Disassociation-Management-Frames, zeigt Zähler,
  Kanal und ein Live-Log mit Quell-MAC. Broadcast-Deauth (an FF:FF:FF:FF:FF:FF,
  trifft alle Clients gleichzeitig) wird rot hervorgehoben.
- **BLE-Tab**: Zählt empfangene BLE-Advertisements pro Sekunde und lernt einen
  gleitenden Basiswert. Fällt die Rate 3 Sekunden in Folge auf unter ~30% des
  Basiswerts, wird ein Alarm ausgelöst – typisches Symptom, wenn jemand den
  2,4-GHz-Bereich stört. **Das ist eine Heuristik, keine Spektrumanalyse** und
  kann False Positives haben (z.B. wenn reale BLE-Geräte in der Nähe abgeschaltet
  werden).

## Rechtliches

Beide Detektoren sind reine Empfänger und in Deutschland unproblematisch.
Ein aktiver Jammer wurde bewusst NICHT umgesetzt – Funkstörsender sind nach
§55 TKG verboten (Bußgeld bis 100.000 €, Einzug durch die Bundesnetzagentur).
