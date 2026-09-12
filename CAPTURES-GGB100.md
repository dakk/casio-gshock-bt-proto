# GG-B100 captures — timelines

Frame-by-frame account of the two screen recordings that accompany the GG-B100
btsnoop dumps, aligned with the BLE traffic, so the videos themselves are no
longer needed. Clock = phone local time (CEST), which is also what the raw
btsnoop timestamps show. BLE columns quote the packets as they appear in
[PROTOCOL-GGB100.md](PROTOCOL-GGB100.md); `r=` is the connection-reason byte of
the BLE_FEATURES reply.

The app is the CASIO WATCHES app in Italian. Recurring strings:
"Connessione in corso…" = connecting overlay, "Invia impostazione all'orologio"
= send-to-watch button, "Impostazioni completate." = settings-sent toast,
"Connessione con GG-B100 terminata." = disconnected toast.

---

## Capture 1 — 2026-09-09

Files: `dumps/ggb100/1/09092026_btsnoop_hci.log` (16:15:41–16:32:16, Casio
traffic 16:16:09–16:26:10) and `dumps/ggb100/1/video_2026-09-09_16-40-27.mp4`
(10:28, 576×1280). **Video 0:00 ≈ 16:16:02** (±2 s, fitted on the three alarm
writes). The watch was already paired; the app is on the GG-B100 settings page
("Il mio orologio › GG-B100") at the start.

| Video | Clock | On screen | BLE |
|-------|-------|-----------|-----|
| 0:00 | 16:16:02 | GG-B100 settings list: Sveglie, Timer, Punto posizione, Impostazione di correzione dell'altitudine, MISSION LOG › Registra informazioni sulla posizione, LIFE LOG › Metodo di calcolo del consumo energetico, Ora mondiale, Sincronizzazione Orario, Regolazione delle lancette, Trova telefono, Impostazioni orologio, Guida | — |
| 0:05 | 16:16:07 | GG-B100 page (watch photo, "4 set 2026"), status "Connessione assente." | — |
| 0:08–0:18 | 16:16:10–20 | "Connessione in corso…" spinner over the page | 16:16:09.7 connect, **r=01**. Full init: `11` r/w, `05/1c` (`26 09 09 14 10 …`), `37 00`, `19` (12 records, no series), `11` (2096 steps / 1002 kcal, hourly [73, 237] / [27, 104]), `20/28 ×2`, city block (Amsterdam as world city), `38` read, time 16:16:18.4; conn-param update 16:16:20 |
| 0:20 | 16:16:22 | Toast "Connessione con GG-B100 stabilita.", status "Connesso" ("Premi un pulsante qualsiasi dell'orologio per disconnetterti") | — |
| 0:30 | 16:16:32 | Sveglie: alarm 1 = 11:56 off, alarms 2–5 = 00:00 off, Segnale off | `15`, `16` read |
| 0:35 | 16:16:37 | Alarm 1 ON and alarm 4 = 03:00 ON, send | 16:16:39.0 `15 40 40 0b 38`, `16 00400000 00400000 40400300 00400000` |
| 0:45 | 16:16:47 | Alarm 4 off, send | 16:16:48.2 `15 40 40 0b 38`, 16:16:48.5 `16 … 00400300 …` |
| 0:55 | 16:16:57 | Alarm 1 off, send; "Impostazioni completate." | 16:16:55.3 `15 00 40 0b 38`, 16:16:55.9 `16 …` all off |
| 1:00 | 16:17:02 | Timer 0 h 12 min, send | 16:17:02.4 `18 00 0c 00…` |
| 1:05–1:10 | 16:17:07–12 | Timer 1 h 12 min, send | 16:17:09.8 `18 01 0c 00…` |
| 1:15 | 16:17:17 | Timer 0 h 11 min, send | 16:17:16.8 `18 00 0b 00…` |
| 1:20 | 16:17:22 | "Punto posizione": existing point "9 set 2026 14:24" at N39°13'5.6" / E9°16'1.6" (Via Chianciano), "Modifica checkpoint"; note "Puoi impostare un solo Punto posizione" | — |
| 1:25 | 16:17:27 | MISSION LOG › "Registra informazioni sulla posizione" toggle already ON (phone-side option, nothing sent) | — |
| 1:30–1:40 | 16:17:32–42 | LIFE LOG › "Uso dei dati di pressione dell'aria per il calcolo dell'energia consumata": off, send; on, send | 16:17:37.2 `13 06 00 … 08 …`, 16:17:43.6 `13 06 00 … 0c …` |
| 1:50 | 16:17:52 | Ora mondiale map, current city Amsterdam (16:17 UTC+2, DST AUTO) | — |
| 1:55–2:00 | 16:17:57–18:02 | London selected (15:17 UTC+1, DST AUTO), sent | 16:17:56.7 `21 00 01`; `1d … f5 76 a0 00`; `1e 01 a0 00 00 04 02`; `24 01` = London; `1f 01 LONDON`; `2f 0c 04`; 16:17:59.8 `21 01 01` |
| 2:05–2:10 | 16:18:07–12 | "Sincronizzazione automatica dell'ora" toggle OFF, sent; then ON, sent | 16:18:12.7 `11 … 80 1e 03`; 16:18:19.1 `11 … 00 1e 03` |
| 2:15–2:20 | 16:18:17–22 | "Sincronizzazione Orario": "Ultima Sincronizzazione Orario 9 set 2026 16:16"; "Cronologia della sincronizzazione automatica dell'ora": 9 set 12:30, 9 set 06:30, 8 set 06:30, 7 set 18:30 | — |
| 2:25 | 16:18:27 | "Trova telefono" page (ringtone Simple/Classic/Jazz, volume, "Test del volume") — viewed only | — |
| 2:30 | 16:18:32 | "Impostazioni orologio" submenu: Suono tasti, Luce, Display orologio, Personalizza Modalità, Impostazioni direzione, Intervallo Misurazione Altitudine, Ora legale, Modifica visualizzazione ora, Tempo di connessione con l'app | — |
| 2:35–2:40 | 16:18:37–42 | "Suono tasti" off, sent; on, sent | 16:18:37.4 `13 04 00 …`; 16:18:43.9 `13 06 00 …` |
| 2:50 | 16:18:52 | "Luce": Luce auto ON + durata 3 s, sent | 16:18:51.0 `13 02 01 …` |
| 2:55 | 16:18:57 | Luce auto OFF + 1,5 s, sent | 16:18:56.2 `13 06 00 …` |
| 3:00–3:10 | 16:19:02–12 | "Display orologio": current = 12 h, Modalità pressione "Spostamenti pressione", Modalità dislivello "Dislivello (±100)"; user picks "sec" for both | — |
| 3:15 | 16:19:17 | "Visualizzazione 24 h" + pressione "sec" + dislivello "sec", sent **in one go** | 16:19:17.3 `13 07 00 … 0c …`; 16:19:17.5 `2f 04 00 00 00 00` |
| 3:25 | 16:19:27 | Back to 12 h / Spostamenti / ±100, sent | 16:19:25.8 `13 06 00 … 0c …`; 16:19:25.9 `2f 0c 04 00 00 00` |
| 3:30 | 16:19:32 | "Personalizza Modalità" (Modalità tab: BAROMETER, TEMPERATURE, RECALL, SUNRISE, STOPWATCH, TIMER, ALARM, WORLD TIME, all on; "Ripristina Impostazioni") — viewed only | 16:19:28.8 `38` read |
| 3:40 | 16:19:42 | "Impostazioni direzione": Correzione automatica OFF, sent; then ON | 16:19:42.7 `13 … 04 …`; 16:19:49.7 `13 … 0c …` |
| 3:55–4:00 | 16:19:57–20:02 | "Intervallo Misurazione Altitudine": 2 min (12 h continue) → 5 s (1 h continua), sent | 16:20:03.0 `2f 08 04 00 00 00` |
| 4:10 | 16:20:12 | Back to 2 min, sent | 16:20:11.5 `2f 0c 04 00 00 00` |
| 4:20–4:25 | 16:20:22–27 | "Ora legale" Rome (16:20 UTC+2, DST 29 mar / 25 ott): AUTO → ON, sent, "Impostazioni completate." | 16:20:22.1 `21 00 03`; `1d 00 01 01 03 …`; `1e`, `24`, `1f`, `2f` rewritten; 16:20:25.2 `21 01 03` |
| 4:30 | 16:20:32 | OFF, sent (Rome now displayed 15:20) | 16:20:30.3 `21 00 03`; `1d 00 01 00 03 …`; 16:20:33.6 `21 01 03` |
| 4:40 | 16:20:42 | AUTO, sent | 16:20:38.8 `21 00 03`; `1d 00 01 03 03 …`; 16:20:42.1 `21 01 03` |
| 4:50–5:00 | 16:20:52–21:02 | "Modifica visualizzazione ora": Ora locale Rome 16:20 / Ora mondiale London 15:20 → after swap London / Rome | — |
| 5:05 | 16:21:07 | Swap sent | 16:21:03.1 `21 00 02`; `1d … a0 00 f5 76`; `1e 00 a0 00 00 04 02`, `1e 01 f5 76 04 04 02`; both `24` swapped; `1f 00 LONDON`, `1f 01 ROME`; 16:21:06.4 `21 01 02` |
| 5:10–5:15 | 16:21:12–17 | Page now shows London 15:21 local / Rome 16:21 world | — |
| 5:20 | 16:21:22 | Swap back, sent | 16:21:20.5 `21 00 02` … 16:21:23.6 `21 01 02` |
| 5:30 | 16:21:32 | "Tempo di connessione con l'app": 5 min, sent | 16:21:30.6 `11 … 1e 05` |
| 5:35 | 16:21:37 | 10 min, sent | 16:21:36.4 `11 … 1e 0a` |
| 5:40 | 16:21:42 | 3 min, sent | 16:21:42.6 `11 … 1e 03` |
| 5:45–6:00 | 16:21:47–22:02 | Settings list, idle | 16:21:51.7 watch disconnects (0x13) |
| 6:05–6:10 | 16:22:07–12 | "Connessione in corso…" over the settings list (nothing tapped) | 16:22:05.7 connect **r=07**: `35 02 00…` → h0009 ×3 → phone `35 02 01 00…` 16:22:14.1 → watch drops 16:22:14.3 |
| 6:15 | 16:22:17 | Toast "Connessione con GG-B100 terminata." | — |
| 6:20 | 16:22:22 | "Il mio orologio" tab: watch list GG-B100 / GBD-200 / SGW-100, header "Operatività della Sincronizzazione Orario" | — |
| 6:25–6:30 | 16:22:27–32 | "Connessione in corso…" on the GG-B100 card, then "terminata" toast | 16:22:24.4 connect r=07: `35 02` → `35 02 01` 16:22:29.5 → drop 16:22:29.8 |
| 6:45 | 16:22:47 | "Connessione in corso…" | 16:22:41.8 connect r=07: `35 00 00…` → phone `35 00 01 00…` 16:22:47.9 → drop 16:22:48.2 |
| 7:00–7:05 | 16:23:02–07 | "Connessione in corso…", then "terminata" toast | 16:22:58.3 connect r=07: `35 02` → `35 02 01` 16:23:03.5 → drop 16:23:03.7 |
| — | 16:23:18 | *Watch: mission log START pressed* | S record `1a00 260909142318` (26 m) |
| 7:20–7:30 | 16:23:22–32 | "Connessione in corso…"; notification "CASIO WATCHES · Calcolo in corso…"; GG-B100 card badge "Calcolo in corso…" | 16:23:19.2 connect **r=08**: `11` r/w, `37 01`, `19` (13 records, S added, no series), `11` (2096 / 1002, hourly empty), `20/28 ×2`, city block, time 16:23:27.3; drop 16:23:28.6 |
| 7:35–7:40 | 16:23:37–42 | Home: "Ultima sincronizzazione Oggi 16:23"; "È stata aggiunta una nuova attività — MISSION LOG mer 9 set 2026 16:23"; LIFE LOG 2.096 passi / 1.238 kcal | — |
| 7:45–8:40 | 16:23:47–24:42 | "La mia pagina": LIFE LOG 2.096 (26 %) / 1.238 kcal (53 %); MISSION LOG card "Dati Punto non disponibili. — Calcolo in corso…" (9 set 16:23); LOCATION POINT map (Via Chianciano) | — |
| — | 16:24:45 | *Watch: GOAL pressed (saves the location point)* | G record `1a00 260909142445` |
| 8:45 | 16:24:47 | "Connessione in corso…" over the MISSION LOG card; LIFE LOG kcal now 1.239 | 16:24:46.2 connect **r=08**: `11` r/w, `37 03 26 09 09 14 24 45`, `19` (14 records, G added, series `26 09 09 14 23 01` = [26 m]), `11` (empty hourly), city block, time 16:24:54.5; drop 16:24:55.6 |
| 8:50–8:55 | 16:24:52–57 | MISSION LOG card shows the track with S/G markers at the same spot | — |
| 9:00–9:05 | 16:25:02–07 | Mission detail "9 set — 9 set 2026 16:23": altitude graph flat at 26 m, "Tempo Attività 0 ora 1 minuto", "Distanza Attività 0,0 km", "Dislivello cumulativo 0,0 m"; S 16:23 N39°13'6.2" / E9°16'2.6" Altitudine 26,0 m; waypoint 16:24 N39°13'5.9" / E9°16'2.1"; G 16:24 "HIGHEST" | — |
| 9:10 | 16:25:12 | Dialog "Indicatore Posizione operativo" | 16:25:08.8 connect **r=07**: `35 02` → phone `35 02 00 01 00 00 00 84 00` (1 m, 132°) 16:25:10.5; poll 16:25:20.6 → `35 02 01` 16:25:24.4; poll 16:25:30.6 → `35 02 00 15 00 00 00 c2 00` (21 m, 194°) 16:25:40.4; poll 16:25:50.7 |
| 9:15–9:50 | 16:25:17–52 | Dialog stays; user walks a few metres | — |
| 9:55 | 16:25:57 | Dialog gone, mission detail page | 16:25:52.8 watch drops |
| 10:05–10:10 | 16:26:07–12 | "Connessione in corso…", then "terminata" toast | 16:26:06.1 connect r=07: `35 00 00…` → phone `35 00 00 00…` 16:26:09.5 → drop 16:26:09.8 |
| 10:15–10:27 | 16:26:17–29 | "La mia pagina": LOCATION POINT card now dated "mer 9 set 2026 16:26" (Via Chianciano), LIFE LOG 2.096 / 1.241 kcal. **End of video.** | No further Casio traffic; log ends 16:32:16 |

---

## Capture 2 — 2026-09-11 (evening) and 2026-09-12 (night/morning)

Files: `dumps/ggb100/2/btsnoop_hci.log.last` (20:02:14 on the 11th → 10:51:53
on the 12th; all the Casio traffic), `dumps/ggb100/2/btsnoop_hci.log` (10:51–
11:22 on the 12th, scan noise only) and `dumps/ggb100/2/video_2026-09-12_09-50-33.mp4`
(17:16, 576×1280; exported on the 12th but recorded on the 11th).
**Video 0:00 ≈ 20:02:05** (±2 s). The phone is in a moving car with Google
Maps navigating the whole time (top pill: distance, ETA, next street); the
Maps pill and the "Torcia" notification are unrelated to the watch.

| Video | Clock | On screen | BLE |
|-------|-------|-----------|-----|
| 0:00–0:04 | 20:02:05–09 | Developer options: "Registro Bluetooth HCI snoop" set to "Attiva" | — |
| 0:05–0:11 | 20:02:10–16 | Control centre: Bluetooth off, then on | Log starts 20:02:14.8 |
| 0:12–0:16 | 20:02:17–21 | Home screen → CASIO WATCHES launched | — |
| 0:16–0:27 | 20:02:21–32 | App Home: GG-B100 "Connessione assente", "Ultima sincronizzazione Oggi 18:30", LIFE LOG 3.920 passi / 1.443 kcal (ven 11 set 18:30) | — |
| 0:28–0:37 | 20:02:33–42 | "GG-B100 Connessione in corso…" overlay on Home (no tap or pull visible before it: the sync was started on the watch) | 20:02:33.3 connect **r=04**: `20/28 ×2`, city block (`24 00` = 39.2181 / 9.1820, Poetto seafront), time 20:02:38.1; **phone** disconnects 20:02:43.2 (0x16) |
| 0:38 | 20:02:43 | Toast "L'ora dell'orologio è stata reimpostata"; "Ultima sincronizzazione Oggi 20:02" | — |
| — | 20:02:49 | *Watch: mission log START pressed* | S record `edff 260911180249` (−19 m) |
| 0:45–0:53 | 20:02:50–58 | "Connessione in corso…"; notification "CASIO WATCHES · Calcolo in corso…" | 20:02:50.6 connect **r=08**: `11` r/w, `37 01`, `19` (oldest record evicted, S appended, no series), `11` (4172 steps / 1920 kcal, hourly [252, 269] / [104, 124]), `20/28 ×2`, city block, time 20:02:59.1; drop 20:02:59.4 |
| 0:54–0:57 | 20:02:59–03:02 | Status "Connesso", then toast "Connessione con GG-B100"; Home: "È stata aggiunta una nuova attività — MISSION LOG ven 11 set 2026 20:02", LIFE LOG 4.172 / 1.569 kcal | — |
| 1:00–12:00 | 20:03–20:14 | Home page unchanged. Driving east along the Poetto seafront to Quartu Sant'Elena (Maps: 1,3 km → arrival 20:15, then SP17, then Via Lipari) | No BLE traffic. Watch samples altitude every 2 min (18:03 … 18:13 UTC) |
| 12:00–12:10 | 20:14:05–15 | Control centre opened; torch switched on (stays on) | — |
| — | 20:14:18 | *Watch: GOAL pressed = location point saved* | G record `faff 260911181419` (−6 m) |
| 12:20 | 20:14:25 | Toast "Connessione con GG-B100"; Home: "Ultima sincronizzazione Oggi 20:14", LIFE LOG 4.195 / 1.585 kcal | 20:14:19.9 connect **r=08**: `11` r/w, `37 03 26 09 11 18 14 18`, `19` (G appended, series `26 09 11 18 03 06` = [−19, −19, −18, −17, −14, −6]), `11` (4195 / 1929, hourly empty), city block (`24 00` = 39.2207 / 9.2525, Via Lipari), time 20:14:28.1; drop 20:14:28.5 |
| 12:30–12:43 | 20:14:35–48 | "La mia pagina": LIFE LOG 4.195 (52 %) / 1.585 kcal (68 %); MISSION LOG map with the S→G track along the coast (Quartu Sant'Elena, Su Forti); "Registro generale 11 set 20:14" | — |
| 12:44–12:45 | 20:14:49–50 | "Connessione in corso…" overlay | 20:14:50.6 connect **r=07**: `35 00 00…` → h0009 → phone `35 00 00 00…` 20:14:52.4 → drop 20:14:52.7 |
| 12:46–12:57 | 20:14:51–15:02 | Toast "Connessione con GG-B100"; LOCATION POINT card appears (pin on Via Lipari, "11 set — ven 11 set 2026 20:14") above LIFE LOG | — |
| 12:58–13:00 | 20:15:03–05 | "GG-B100 Connessione in corso…" on the LOCATION POINT map | 20:15:00.7 connect **r=07**: `35 02 00…` → h0009 → phone `35 02 00 00 00 00 00 00 00` 20:15:03.4; conn-param update 20:15:04 |
| 13:02 | 20:15:07 | Dialog "Indicatore Posizione operativo — Questa funzione verrà disattivata quando la connessione con l'orologio sarà interrotta. Premi il pulsante CONNECT sull'orologio per estendere l'attivazione della funzione. Premi un qualsiasi altro pulsante per interrompere la connessione." (stays until 14:28) | Poll 20:15:13.6 → `35 02 00 00…` 20:15:15.4; poll 20:15:23.6 → `35 02 00 1f 00 00 00 ac 00` (31 m, 172°) 20:15:24.4 |
| 13:36 | 20:15:41 | Maps: at Via Lipari ("10 m"), then re-routes to SP17 | Poll 20:15:39.5 → `35 02 01 00…` 20:15:41.4 |
| 14:17 | 20:16:22 | Maps: SP17 500 m | Poll 20:16:21.6 → `35 02 01 00…` 20:16:22.4 |
| 14:28–14:30 | 20:16:33–35 | Dialog closes; LOCATION POINT map visible | 20:16:32.9 watch drops (0x13) |
| 14:31–14:35 | 20:16:36–40 | Toast "Connessione con GG-B100" | — |
| 14:43 | 20:16:48 | — | 20:16:47.9 connect **r=07**: `35 02` → h0009 → phone `35 02 00 77 03 00 00 0c 01` (887 m, 268°) 20:16:50.2; conn-param update 20:16:51 |
| 14:48–14:51 | 20:16:53–56 | "GG-B100 Connessione in corso…" on the map, pin labelled "GG-B100" | — |
| 14:52 | 20:16:57 | Dialog "Indicatore Posizione operativo" back (stays to the end of the video) | 20:17:11.4 `35 02 00 90 04 00 00 10 01` (1168 m, 272°); 20:17:25.4 `… be 04 00 00 11 01` (1214 m, 273°) |
| 15:45–16:00 | 20:17:50–18:05 | Maps: "Arrivato" — home, Via Chianciano | 20:18:11.6 and 20:18:30.7 `35 02 01 00…`; 20:18:38.4 `… 26 05 00 00 1b 01` (1318 m, 283°); then 1289, 1307, 1289, 1307, 1307, 1307, 1307 m at 283° every 10–20 s |
| 16:00–17:16 | 20:18:05–19:21 | Notification shade: Maps "Arrivo a Casa"; "Collegamento orologio avviato. Se elimini il collegamento, alcune funzioni…" (CASIO foreground service); Gadgetbridge "No devices connected — Scanning 1 device"; "Torcia — La torcia è attiva". **End of video 17:16.** | Session continues: 1296, 1295 (282°), 1284, 1290, 1281 (282°), 1287 m/283° until 20:21:10.6; 20:21:17.7 watch drops (0x13) |

After the recording (log only):

| Clock | BLE |
|-------|-----|
| 20:29:36 | Watch connects; link encrypted, ALL_FEAT CCCD enabled, MTU exchanged; app never writes `22`; watch drops 20:29:43 |
| 00:30:31 (12th) | Same silent connection (scheduled slot, app not running); drops 00:30:38 |
| 06:30:30 (12th) | Scheduled sync **r=03**: `05/1c` (`26 09 11 06 30 …`), `37 00`, `19` (same 14 records, series cleared), `11` (today 0 / 0; hourly [0×7, 197, 92, 311] / [0×7, 89, 38, 128]; history [4772, 2175]), `20/28 ×2`, city block (`24 00` = 39.2182 / 9.2670, home), h0009, `36 00 01 08 00` → `36 00 01 00 00`, time 06:30:40.7; supervision timeout 06:30:45.8 |
| 10:51–11:22 | Log rotated to `btsnoop_hci.log`: LE scan reports and cancelled auto-connect attempts only |
