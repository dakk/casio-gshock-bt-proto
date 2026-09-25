# GG-B100 captures — timelines

Frame-by-frame account of the screen recordings that accompany the GG-B100
btsnoop dumps, aligned with the BLE traffic, so the videos themselves are no
longer needed (capture 6 has no video — log only). Clock = phone local time
(CEST), which is also what the raw btsnoop timestamps show in captures 1, 2
and 6 (in captures 3 and 5 they run 2 h ahead).
BLE columns quote the packets as they appear in
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

---

## Capture 3 — 2026-09-14

Files: `dumps/ggb100/3/btsnoop_hci.log.last` (raw ts 08:30–16:12) and
`dumps/ggb100/3/btsnoop_hci.log` (16:19–16:25), plus
`dumps/ggb100/3/video_2026-09-14_16-50-29.mp4` (1:47, 576×1280, exported 16:50).
**The raw btsnoop timestamps run 2 h ahead of phone local time in this
capture** — all times below are local, taken from the payload BCD values and
the status-bar clock. **Video 0:00 ≈ 14:21:48** (±3 s, fitted on the four
`0x38` writes and the 14:21→14:22 clock flip at 0:10–0:15).

The day before the recording (`.log.last`, log only — no video): a 4-hour
hiking mission. The watch connected on its own about every hour while the
mission ran; each connection is the normal `r=08` flow and each ACK consumes
the altitude series and the LIFE LOG bins accumulated so far.

| Clock | Event / BLE |
|-------|-------------|
| 06:30:31 | Scheduled sync **r=03**: `05/1c` (`26 09 13 06 30 …` = yesterday's slot), `37 00`, `19` (same 14 records as capture 2, series cleared), `11` (456 steps / 282 kcal, 18 hourly bins, history [3491, 1605] = the 13th), `20/28 ×2`, city block, h0009, `36 00 01 08 00` → `36 00 01 00 00`, time 06:30:41; supervision timeout 06:30:4x (0x08) |
| 10:14:05 | *Watch: mission START pressed at 301 m* → connect **r=08** 10:14:07: `11` r/w, `37 01`, `19` (S record `2d01 260914081405` appended, `260906212830` evicted; series still empty), `11` (7224 / 4458, bins [3366, 2584, 756, 0]), city block, time 10:14:16; drop (0x13) |
| 11:12:32 | Offload **r=08**: `37 02 ff…`, `19` (series `26 09 14 08 14`, 30 samples: 300 276 254 … 19 m), `11` (10042 / 5758, bin 2218 / 1059), time 11:12:40; drop |
| 12:12:33 | Offload **r=08**: `37 02`, series `26 09 14 09 14`, 30 samples (17 … 2 m); `11` (11479 / 6409, bin 2099 / 919); time 12:12:41; drop |
| 13:13:31 | Offload **r=08**: `37 02`, series `26 09 14 10 14`, 30 samples (2 … 4 m); `11` (12496 / 7045, bin 874 / 581); time 13:13:40; drop |
| 13:31:43 | Phone connects to an unrelated Google Fast Pair device `57:d7:e2:6c:37:94` (full GATT discovery, key exchange on h0025) — **not the watch** |
| 14:12:31 | Offload **r=08**: `37 02`, series `26 09 14 11 14`, 30 samples; `11` (13050 / 7280, bin 505 / 208); time 14:12:39; drop |

Then the main log (`.log`) and the video:

| Video | Clock | On screen | BLE |
|-------|-------|-----------|-----|
| — | 14:19:19 | *Watch: GOAL pressed at 5 m = location point saved* | connect **r=08** 14:19:21: `11` r/w, `37 03 26 09 14 12 19 19`, `19` (series `26 09 14 12 14` = [5, 5, 5]; G record `0500 260914121920` appended, `260906212858` evicted), `11` (13050 / 7280, bins empty — 14:12 offload just consumed them), `20/28 ×2`, city block, time 14:19:30; drop 14:19:3x (0x13) |
| — | 14:19:44 | (before the video) app opened | connect **r=01**: full init: `11` r/w, `05/1c` (`26 09 14 06 30 …` = that morning's sync), `37 00`, `19` (series gone, same 14 records), `11` (same, empty), `20/28 ×2`, city block, `38` read, time 14:19:48; conn-param update; h0009 read 14:20:3x |
| 0:00 | 14:21:48 | "Impostazioni orologio › Personalizza Modalità", **Mostra** tab: 5 screens on ("Grafico Pressione Barometrica …", STEPS (TODAY), SUNRISE/SUNSET (TODAY), Giorno e data, ore / min / sec), 3 off (YEAR DATE, Grafico Pressione Barometrica, Ora Mondiale HH MM); "Ripristina Impostazioni" | 14:21:26.7 `11` read, 14:21:35.4 `38` read (page open) |
| 0:01–0:06 | 14:21:49–54 | The three off screens switched ON (all 8 on), "Invia impostazione all'orologio", spinner | 14:21:55.9 `38 01 02 03 04 05 06 07 08 03 07 08 01 05 02 04 06`, re-read verifies |
| 0:10–0:20 | 14:21:58–22:08 | Back to the "Impostazioni orologio" menu | 14:22:07–11 app re-reads `11` / `13` / `2f` / `38` |
| 0:25–0:39 | 14:22:13–27 | Mostra tab again (all 8 on); YEAR DATE, Grafico Pressione Barometrica, Ora Mondiale HH MM switched off; GPB back on (6 on), send | 14:22:29.9 `38 … 03 07 08 01 05 04 ff ff`, re-read ×2 |
| 0:40 | 14:22:28 | "Impostazioni completate."; list re-sorted (shown screens first) | — |
| 0:45–1:10 | 14:22:33–58 | **Modalità** tab: BAROMETER, TEMPERATURE, RECALL, SUNRISE, STOPWATCH, TIMER, ALARM, WORLD TIME, all on; WORLD TIME off (~1:05), then RECALL off (~1:10) | — |
| 1:15 | 14:23:03 | Warning: "Le categorie impostate saranno disattivate per le funzioni inutilizzate dell'orologio. Vuoi proseguire? (Esempio: la sveglia sarà disattivata.)" — dismissed; RECALL back on (~1:25) | — |
| 1:30–1:35 | 14:23:18–23 | Warning again, OK; sent with only WORLD TIME off | 14:23:20.3 `38 01 02 03 04 05 06 07 ff 03 07 08 01 05 04 ff ff`, re-read ×2 |
| 1:37–1:40 | 14:23:25–28 | WORLD TIME back on, sent; back to the menu | 14:23:26.7 `38 01 02 03 04 05 06 07 08 03 07 08 01 05 04 ff ff`, re-read |
| 1:45–1:46 | 14:23:33 | "Il mio orologio" watch list (GG-B100 / GBD-200 / SGW-100). **End of video.** | — |

After the recording (log only):

| Clock | BLE |
|-------|-----|
| 14:23:49 | Manual sync (CONNECT on the watch) **r=04**: `20/28 ×2`, city block, time 14:23:53; **phone** disconnects 14:23:5x (0x16) |
| 14:24:48 | Silent connection: no `22`; the phone's GATT server sends the watch a Service Changed indication (`h0003`, `01 00 ff ff`); watch drops ~7 s later (0x13) |
| 14:25:03 | **r=07**: `35 02 00…` → h0009 ×2 → phone `35 02 01 00…` (nothing to give, although a point was saved at 14:19 — presumably no GPS fix); drop (0x13) |
| 14:25:17 | **r=07** again, identical exchange, drop (0x13); no further Casio traffic |

---

## Capture 5 — 2026-09-17

Files: `dumps/ggb100/5/btsnoop_hci.log.last` (raw ts 20:38–20:39),
`dumps/ggb100/5/btsnoop_hci.log` (raw ts 20:45:51–20:49:04) and
`dumps/ggb100/5/video_2026-09-17_18-53-38.mp4` (3:29, 576×1280, exported 18:53).
`5/btsnoop_hci_4.log` is a byte-identical duplicate of `.log.last`.
**The raw btsnoop timestamps run 2 h ahead of phone local time** — all times
below are local. **Video 0:00 ≈ 18:45:45** (±5 s, fitted on the r=01 connect
overlay at 0:42 and the `0x38` write at 1:12).

The location point (dated 18:39) exists for the whole capture — its card never
leaves "La mia pagina". The main-log Location Indicator sessions are answered
`<st>=01` not because the point is gone but because the phone has no usable GPS
fix (indoors, app just opened or in the background; an outdoor retest with a
good fix was served immediately). At 18:45:24 the user recorded a standalone
altitude point (REC) on the watch; a REC opens no connection and sets no flag
(capture 6 proves it), so the record simply waited on the watch until the
18:46 app session fetched it — it appears on the app timeline as an ALTITUDE
card with "Dati Punto non disponibili" (the record has altitude and time only,
no position).

The rotated `.log.last`, log only — the point still exists:

| Clock | BLE |
|-------|-----|
| 18:38:47 | connect **r=07** (watch in indicator mode): `35 02 00…` → h0009 ×2 → phone `35 02 00 10 15 00 00 24 01` (5392 m, 292° — stale phone fix) 18:38:51; watch drops (0x13) |
| 18:39:08 | connect **r=07**: `35 00 00…` → h0009 → phone `35 00 00 00…` (point exists, nothing to show outside indicator mode) 18:39:10; drop (0x13) |

Then the main log and the video:

| Video | Clock | On screen | BLE |
|-------|-------|-----------|-----|
| — | 18:45:51 | (video not started yet) | connect **r=07**: `35 02` → h0009 ×2 → phone `35 02 01` (no usable fix) 18:45:59; drop |
| 0:00–0:10 | 18:45:45–55 | Home screen → CASIO WATCHES opened, "La mia pagina": LOCATION POINT card (pin on Via Chianciano, "17 set — gio 17 set 2026 18:39"), LIFE LOG 2.764 passi / 1.422 kcal | connect **r=07** 18:46:10: `35 00` → h0009 ×2 → phone `35 00 01` 18:46:13; drop |
| 0:20–0:38 | 18:46:05–23 | Page scrolled: LOCATION POINT card still shown, kcal 1.422 | — |
| 0:40–0:55 | 18:46:25–40 | "Connessione in corso…" overlay; when the sync finishes the timeline gains an **ALTITUDE card "Dati Punto non disponibili."** dated "17 set 18:45" (the standalone REC in the `19` fetch — altitude only, no position) under "Registro generale: 17 set 18:46"; the LOCATION POINT card stays below it; toast "Connessione con GG-B100 stabilita." | 18:46:23.9 connect **r=01**: full init: `11` r/w, `05/1c` (`26 09 17 18 30 …` = the 18:30 scheduled slot), `37 00`, `19` (no series, 14 records — FIFO fully rolled since cap 3, newest `0700 260917164524` = the 18:45:24 local REC), `11` (2764 steps / 1196 kcal, bins and history empty), `20/28 ×2`, city block (ROME/LONDON, `2f 0c 04`), `38` read (`01 02 04 05 06 08 03 07 | 03 07 08 01 05 04 ff ff`), time 18:46:32; conn-param update |
| 0:50–1:05 | 18:46:35–50 | GG-B100 page ("Connesso") → Impostazioni orologio → "Personalizza Modalità", Modalità tab: BAROMETER, TEMPERATURE, SUNRISE, STOPWATCH, TIMER, RECALL, WORLD TIME, ALARM (the post-write order — see below) | app re-reads `11` 18:46:43 and `38` 18:46:48 |
| 1:05–1:15 | 18:46:50–1:00 | RECALL dragged above WORLD TIME, "Invia impostazione all'orologio", "Impostazioni completate." | 18:46:53.3 `38 01 02 04 05 06 03 08 07 …` (positions 6/7 swapped), re-read verifies 18:46:53.8 |
| 1:18–1:30 | 18:47:03–15 | "Suono tasti": toggle OFF, sent; back ON, sent | 18:46:58.7 `11` read; `13 06…` read 18:46:59; 18:47:05.4 `13 04 00 …`; re-reads (`11`, `13 04…`) 18:47:08; 18:47:11.0 `13 06 00 …` |
| 1:40–2:00 | 18:47:25–45 | Sveglie page: alarms 1–5 all off (11:56, 00:00, 00:00, 03:00, 00:00), "Segnale" toggled ON then OFF, sent — "Impostazioni completate." | `15`/`16` read 18:47:31; 18:47:35.2 `15 80 40 0b 38` (**chime on**) + `16` rewritten unchanged; re-reads 18:47:38–39 (`15 80 00 0b 38`); 18:47:41.8 `15 00 40 0b 38` (chime off) + `16` again |
| 2:00–2:10 | 18:47:45–55 | Back through the settings menu; "Connessione in corso…" spinner over the menu | app session ends 18:47:42 (watch drops, 0x13); connect **r=07** 18:47:52: `35 02` → h0009 ×2 → `35 02 01` 18:47:57; drop |
| 2:10–2:20 | 18:47:55–18:48:05 | Settings list (Sveglie, Timer, Punto posizione, … Trova telefono, Impostazioni orologio) | connect **r=07** 18:48:10: `35 02` → `35 02 01` 18:48:15; drop |
| 2:20–2:40 | 18:48:05–25 | App backgrounded → phone home screen | connect **r=07** 18:48:26: `35 00` → `35 00 01` 18:48:31; drop |
| 2:40–2:55 | 18:48:25–40 | CASIO WATCHES reopened, "Il mio orologio" watch list; toast "Connessione con GG-B100 terminata." | — |
| ~3:00–3:05 | 18:48:44–50 | *Watch: phone finder triggered* (no UI on the phone — the app just rings) | 18:48:44.0 connect **r=02**: watch pushes `0a 02` immediately (before the `22` reply), prefix `22`/`10`/`23` only; 18:48:50.0 watch pushes `0a 00` (finder stopped from the watch) and drops (0x13) |
| 3:15–3:20 | 18:49:00–05 | "Connessione in corso…" on the GG-B100 card, then the plain list. **End of video 3:29.** | connect **r=07** 18:48:58: `35 02` → h0009 ×2 → `35 02 01` 18:49:03; drop (0x13); no further Casio traffic |

---

## Capture 6 — 2026-09-22

File: `dumps/ggb100/6/btsnoop_hci.log` (Casio traffic 07:11:03–13:13:21).
**No video — log only.** Raw timestamps equal phone local time (as in captures
1–2). The day in one paragraph: a morning app session after four unsynced
days, a Location Indicator walk (with three standalone altitude RECs pressed
on the watch), the altitude-measurement interval toggled 2 min → 5 s → 2 min,
a 3.5-hour mission with two *failed* hourly offload attempts, and the first
captured 12:30 scheduled sync. All time writes carry dow byte `02` (Tuesday ✓)
and land ~0.5 s ahead of the log timestamp (`fractions256` confirmed).

| Clock | BLE |
|-------|-----|
| 07:11:03 | App session **r=01**: `05/1c` = `26 09 18 07 44 …` — **last `01`/`03` connection was Sep 18 07:44, four days earlier**; `37 00`; `19`: series empty, 14 records (newest the Sep-18 07:44 pair, 5 m / 6 m); `11`: today 118/54, **all 24 hourly bins full** (older hours' granularity gone), **4 of 7 day-slots filled** (4285/2077, 1843/773, 2811/1186, 5140/2174 = Sep 21→18); city block, `38`, time 07:11:12. Idle ~3 min → watch drops 07:14:12 (the 3-min "Tempo di connessione" timeout of `11`) |
| 07:44:25 | Silent connection, no `22`; drop 07:44:32 (0x13) |
| 07:47:33 | Manual sync **r=04**: `20/28 ×2`, city block, time 07:47:37; ends ~5 s later. **Does not update the `05/1c` timestamp** (next fetch still says 07:11) |
| 07:47:48 | App session **r=01**: `05/1c` = `…07 11` ✓, `37 00`, `19` (unchanged), `11` (667/276, bins consumed), time 07:47:56; drop 07:48:01 |
| 07:48:17 | **r=07**: `35 02` → `35 02 01` (app just opened, no GPS fix yet); drop 07:48:22 |
| 07:48:39 | **r=07**, live Location Indicator while walking outdoors: polls ~10 s answered 2 m/151°, 2 m/151°, 11 m/94°, 30 m/77°, 23 m/69°, 19 m/59°, 6 m/130°, 2 m/122° (away from the point and back); drop 07:50:27 |
| 07:50:37 | **r=07**: `35 00` → `35 00 00` (point stored, nothing to show outside indicator mode); drop 07:50:41 |
| 07:50:49–07:51:03 | *Watch: three standalone altitude RECs (−13 m)* — **no connection, no `37` flag** |
| 07:51:12 | App session **r=01**: `05/1c` = `…07 47` ✓, `37 00` (RECs pending but unflagged), `19`: the three RECs are in the FIFO, three oldest evicted; `11` (765/317); time 07:51:20; drop 07:51:27 |
| 07:53:40 | Silent connection, phone hangs up 07:53:46 (0x16), no ATT |
| 07:53:54 | App session **r=01**: `05/1c` = `…07 51` ✓ (time written 07:54:02, block records the connect minute); settings reads (`13`, `11`, `38`, `2f`); **altitude interval toggle**: `2f 0c 04` → `2f 08 04` (5 s) 07:55:15, re-read, back to `2f 0c 04` (2 min) 07:55:22; drop 07:56:02 |
| 07:56:10 | *Watch: mission START (−13 m)* → connect **r=08** 07:56:12: `37 01`, `19` (S record `f3ff 260922055610` appended, oldest evicted), `11` (765/317), city block, time 07:56:19; drop 07:56:20 |
| 08:54:31 | **Hourly offload attempt fails**: silent connection (Service Changed IND on `h0003`, CCCD, MTU, no `22`); drop 08:54:38 (0x13) |
| 09:04:33 | Offload retry **r=08**: `37 02`, series `26 09 22 05 56` = **35 samples** (−13 … 130 m — lap stretched to 70 min by the failed attempt), `11` (3630/2022, bins 2586/762), time 09:04:43; drop |
| 10:04:30 | Second failed offload attempt (same silent pattern); drop 10:04:37 |
| 10:14:33 | Offload retry **r=08**: series `26 09 22 07 06`, 35 samples (146 … 285 m); `11` (5787/3617, bin 2207); drop 10:14:43 |
| 10:48:14 | **r=07** mid-mission: `35 00` → `35 00 01` (app in background, no fix); drop 10:48:19 |
| 11:14:32 | Offload **r=08**: series `26 09 22 08 16`, 30 samples (286 … −18 m); `11` (9258/5326, bin 2795); drop 11:14:40 |
| 11:23:37 | *Watch: GOAL (−16 m) = location point saved* → connect **r=08** 11:23:39: `37 03 26 09 22 09 23 36`, series `26 09 22 09 16` = [−19, −17, −17, −17], G record `f0ff 260922092337`; `11` (9582/5449, bins empty); time 11:23:46; drop 11:23:47 |
| 12:30:33 | **Scheduled sync r=03 — the first captured 12:30 slot**: `05/1c` = `…07 53` (mission offloads don't update it), `37 00`, `19` (series gone, same 14 records), `11` (10637/6563, bin 2192), `20/28 ×2`, city block, then **five `h0009` reads ~3.2 s apart (15 s)**, `36 01 01 00 00` (byte[1]=01, unlike the 06:30 slots' `36 00 01 08 00`) → echo identical, arriving *after* the time write 12:30:56; drop 12:31:01 (0x08) |
| 13:11:11 | App session **r=01**: `05/1c` = `26 09 22 12 30 …` ✓ (the 12:30 sync), `37 00`, `19` (unchanged), `11` (10677/6597, bin 40); idle; drop 13:14:19 |

---

## 2026-09-25 — offline mission test (screenshot only, no log)

File: `dumps/ggb100/photo_2026-09-25_16-42-29.jpg` (app mission-detail page).
The BT snoop was off, so there is no packet log — what follows is the app side
only.

A mission was started on the watch at **08:33 (S, 567 m)** with the phone
disconnected, left running offline all day, and ended at **14:20 (G, 43 m)** —
**5 h 47 min**. It synced fine after reconnecting: **the mission does NOT stop
without the hourly connection** (the earlier watch-side suspicion is
withdrawn). The detail page shows:

- the altitude graph spanning the whole 347 min: flat 567 m for ~100 min, a
  suspiciously straight ~2 h descent, then a plateau at ~17 m that does not
  match the G record (43 m);
- waypoints: S 08:33 (567 m), **HIGHEST 10:26 (567 m)** — ≈ when the
  60-sample buffer would first fill at the 2-min interval — a plain waypoint
  at 14:20 (43 m), G 14:20 (43 m), all **altitude-only, no coordinates**;
- "Tempo Attività 5ora47minuto", "**Distanza Attività 0,0km**" (no phone GPS
  track, so no map and presumably no location point saved at GOAL),
  "Dislivello cumulativo 54,0m" (ascent only, apparently).

What the watch sent for the middle 3.5 hours (wrapped series + app-side
interpolation? on-watch compaction? a checkpoint record at buffer-full?) is
unknown — see the "Open" note in
[PROTOCOL-GGB100.md](PROTOCOL-GGB100.md#mission-log-block-0x19-on-data_req_sp)
and the corresponding TODO item. If the test is repeated, keep the HCI snoop
on for the reconnection sync.
