# Casio GG-B100 (Mudmaster) BLE Protocol

Reverse-engineered from three btsnoop HCI captures correlated with screen recordings
of the official CASIO WATCHES app:

| Capture | Files | What happens |
|---------|-------|--------------|
| 1 (2026-09-09, 16:16–16:26) | `dumps/ggb100/1/09092026_btsnoop_hci.log` + `1/video_2026-09-09_16-40-27.mp4` | app-driven session: settings, alarms, world time, a short mission log, first Location Indicator test |
| 2 (2026-09-11, 20:02–20:21 + 2026-09-12 00:30/06:30) | `dumps/ggb100/2/btsnoop_hci.log.last` + `2/video_2026-09-12_09-50-33.mp4` | manual sync, a 12-minute mission log recorded on the watch while driving, a saved location point and a Location Indicator session to it, then the overnight scheduled syncs |
| 3 (2026-09-14, 06:30–14:25) | `dumps/ggb100/3/btsnoop_hci.log.last` (06:30–14:12) + `3/btsnoop_hci.log` (14:19–14:25) + `3/video_2026-09-14_16-50-29.mp4` | scheduled sync, a 4-hour hiking mission with **hourly watch-initiated offload connections**, then an app session editing the mode/display customization (`0x38` writes), a manual sync and two Location Indicator checks |

A frame-by-frame timeline of the recordings, aligned with the packets, is in
[CAPTURES-GGB100.md](CAPTURES-GGB100.md); "video m:ss" references below point
into it. Video 1 `0:00` ≈ 16:16:02, video 2 `0:00` ≈ 20:02:05, video 3 `0:00` ≈ 14:21:48.

Notes on capture 2: the file `2/btsnoop_hci.log` (next morning, 10:51–11:22) contains
only scan noise — the whole session is in the rotated `.log.last`. The video was
exported on the 12th but shows the evening of the 11th. In captures 1–2 the raw
btsnoop timestamps equal the phone's local time (CEST); in capture 3 they run 2 h
ahead of it (the BCD timestamps inside the payloads, and the phone's status-bar
clock in the video, are authoritative). Capture 3 also contains a connection to an
unrelated Google Fast Pair device (`57:d7:e2:6c:37:94`, 13:31) — ignore it; the
watch is `d0:2d:d6:5d:78:28`.

Confidence: fields marked **(?)** are single-observation guesses; everything else
was observed at least twice with matching on-screen actions.

---

## Transport

Same GATT layout as the GBD-200 (service base `26ebXXXX-b012-49a8-b1f8-394fb2032b0f`):

| Name         | UUID (26eb…) | ATT handle | Direction |
|--------------|--------------|------------|-----------|
| ALL_REQ      | `002c`       | `h000c`    | phone→watch (write no-rsp) |
| ALL_FEAT     | `002d`       | `h000e`    | phone→watch (write) + watch→phone (notify) |
| ALL_FEAT-CCC | —            | `h000f`    | CCCD |
| DATA_REQ_SP  | `0023`       | `h0011`    | phone→watch (write) + notify |
| DATA_REQ-CCC | —            | `h0012`    | CCCD |
| CONVOY       | `0024`       | `h0014`    | watch→phone (notify) |
| CONVOY-CCC   | —            | `h0015`    | CCCD |

Plus an unidentified 1-byte characteristic at `h0009` (before the Casio service):
the app READ_REQs it whenever it is idle in a background connection (every ~3 s
while waiting, and once before every Location Indicator write); it always returns
`0xfa`. Neither capture contains GATT discovery, so its UUID is unknown.
Keepalive / status poll **(?)**.

Key transport differences from the GBD-200:

- **No XOR anywhere.** CONVOY payloads are plain; "no data" is encoded with
  sentinels (`0x7fff`, `0xfffe`, `0xfffffffe`) instead.
- **No CONVOY cap/init handshake** (no `04` cap_query / `06` init_sig packets) and
  no `09`/`07` DATA_READY signals. A data request on `h0011` is answered directly
  by a `h0011` echo carrying the length plus CONVOY notifications, then ACKed.
- No `0x47` INITIALIZED event, no `0x3d` main-menu resync, no notification
  characteristic seen.
- The **watch initiates almost every connection** (button presses, mission-log
  events, scheduled time adjustment, Location Indicator mode): it starts
  advertising and the phone's pending background connection completes. The
  watch then tells the app *why* it connected in the BLE_FEATURES reply (see
  [Connection reasons](#connection-reasons)) and the app runs a different flow
  for each reason.
- Long-lived sessions (foreground app, Location Indicator) switch connection
  parameters right after init (LE connection update: interval 90 ms, latency 4,
  supervision timeout 6 s); the short watch-initiated flows never do.

Disconnect reasons seen: `0x13` (watch hangs up — the normal end of every
watch-initiated flow), `0x16` (phone hangs up — end of the manual time sync),
`0x08` (supervision timeout — the watch simply stops answering at the end of the
scheduled sync).

### DATA_REQ_SP request format

```
[op] [feat] {params}
op 0x00 = request, 0x04 = ACK
```

```
phone → h0011  00 <feat> 00 00 00        # plain fetch (feat 0x11, 0x19)
watch → h0011  00 <feat> <len_lo> <len_hi> 00 00 00
watch → h0014  <plain payload, one or more notifications>
phone → h0011  04 <feat> 00 00 00        # ACK — the watch marks the data as consumed

phone → h0011  00 05 1c 00 00            # status block (feat 0x05, param 0x1c)
watch → h0014  <28 bytes>                # answered on CONVOY only, no h0011 length echo
phone → h0011  04 05 1c 00 00
```

The official app toggles the `h0012`/`h0015` CCCDs off and on around every fetch
(for the status block only `h0015`).

---

## Feature IDs

| ID     | Name                | ID     | Name                          |
|--------|---------------------|--------|-------------------------------|
| `0x05` | STATUS_BLOCK (?)    | `0x1f` | WORLD_CITY name (slotted)     |
| `0x09` | CURRENT_TIME        | `0x20` | VERSION_INFO                  |
| `0x10` | BLE_FEATURES (+ connection reason) | `0x21` | TRANSACTION begin/end |
| `0x11` | BLE_SETTINGS        | `0x22` | APP_INFO (read-only here)     |
| `0x13` | BASIC settings      | `0x23` | WATCH_NAME                    |
| `0x15` | ALARM 1             | `0x24` | GPS coords phone / world city |
| `0x16` | ALARMS 2–5          | `0x28` | WATCH_COND                    |
| `0x18` | COUNTDOWN TIMER     | `0x2f` | SENSOR/DISPLAY config         |
| `0x19` | MISSION LOG data (DATA_REQ) | `0x35` | LOCATION INDICATOR session |
| `0x1d` | DST/city state      | `0x36` | unknown, scheduled sync only (?) |
| `0x1e` | DST setting (slot)  | `0x37` | NEW_DATA status               |
| `0x11` | LIFE LOG (DATA_REQ context) | `0x38` | MODE/DISPLAY customization |

Note the overload: `0x11` on ALL_REQ is BLE_SETTINGS, but `00 11 00 00 00` on
DATA_REQ_SP fetches the LIFE LOG block. Same pattern as the GBD-200's context
reuse of feature ids.

---

## Connection reasons

Every connection starts the same way:

```
phone → AF_CCC    01 00
phone → ALL_REQ   22                            # APP_INFO (read only)
watch → ALL_FEAT  22 2255f65569262c6bb97b02     # stored token, last byte 02 = capability
phone → ALL_REQ   10                            # BLE_FEATURES
watch → ALL_FEAT  10 28785dd62dd07f <r> 030f ffffffff 27 000000
phone → ALL_FEAT  23 "CASIO GG-B100\0…"         # identity confirm (WRITE_REQ)
```

`<r>` (byte 8 of the BLE_FEATURES reply) is **the reason the watch connected**.
Observed values, the on-screen trigger, and the flow the app runs in response:

| `<r>` | Seen | Trigger | App flow after `22/10/23` |
|-------|------|---------|---------------------------|
| `01` | cap 1, 16:16 | connection started from the app's watch page ("Connessione assente" → "Connessione in corso…", video 1 0:05–0:10) | `11` r/w, `05/1c`, `37`, `19`, `11`, `20/28 ×2`, city block, `38`, `09`; stays connected for minutes |
| `03` | cap 2, 06:30 | scheduled automatic time adjustment | `05/1c`, `37`, `19`, `11`, `20/28 ×2`, city block, `h0009` read, `36`, `09`; watch drops 5 s later (timeout) |
| `04` | cap 2, 20:02:33 | manual sync (CONNECT on the watch; no in-app tap is visible on the video). App shows "Connessione in corso…" then "L'ora dell'orologio è stata reimpostata" | `20/28 ×2`, city block, `09` — **time only**, no data fetch; phone hangs up 5 s later |
| `07` | all, many | watch in Location Indicator mode (or the app waiting for it) | `35` exchange only, see below |
| `08` | all, many | mission log START or GOAL pressed on the watch — **and ~hourly while a mission runs** (offload, see [Mission log](#mission-log-block-0x19-on-data_req_sp)) | `11` r/w, `37`, `19`, `11`, `20/28 ×2`, city block, `09`; watch drops 0.3 s after the time write |

"city block" = `1d` r/w, `1e ×2` r/w, `24 ×2` w, `1f ×2` r/w, `2f` r/w — the app
re-reads and rewrites the whole world-time state on every full connection even
when nothing changed.

Full flow of an `08` connection (mission log start, capture 2, 20:02:50):

```
phone → ALL_REQ   11        → reply + echo      # BLE_SETTINGS
phone → ALL_REQ   37        → 37 01 ff…         # NEW_DATA: mission record pending
phone → h0011     00 19 00 00 00                # mission-log block (294 bytes on CONVOY)
phone → h0011     00 11 00 00 00                # LIFE LOG block (160 bytes)
phone → ALL_REQ   20 / 28 / 20 / 28             # VERSION_INFO + WATCH_COND ×2
phone → ALL_REQ   1d        → reply + echo
phone → ALL_REQ   1e ×2     → replies + echoes
phone → ALL_FEAT  24 00 01 <lat f64 BE> <lon f64 BE> 04   # phone position
phone → ALL_FEAT  24 01 01 <lat f64 BE> <lon f64 BE> 04   # world-city coords
phone → ALL_REQ   1f 00 / 1f 01 → replies + echoes
phone → ALL_REQ   2f        → reply + echo
phone → ALL_FEAT  09 <time>                     # CURRENT_TIME — ends the init
```

No `47 01` confirmation follows; the time write is always the last step. The
data fetches (`19`, `11`) are done regardless of what `37` reported (the `03`
flow fetched both after a `37 00`).

Observed replies:

```
20 23070101 000…                # version info
28 19 19 00                     # watch condition (0x19 = 25 ×2 — battery? (?))
22 …02                          # APP_INFO: 10-byte token + capability byte
11 0f0f0f 06 00 50 00 04 00 01 00 <a> <b> <t>   # BLE_SETTINGS, see below
```

### Silent / failed connections

At 20:29:36 and 00:30:31 (capture 2) the watch connected, the link was
encrypted and the phone enabled the ALL_FEAT CCCD and exchanged MTU, but the app
never wrote `22`; the watch dropped after ~7 s. The app's own
"Cronologia della sincronizzazione automatica dell'ora" (video 1 2:15) lists
past auto-adjusts at 06:30, 12:30 and 18:30, so 00:30 completes the usual
four Casio slots; these look like scheduled attempts made while the app
process was not running, and the 06:30 slot then succeeded with the `03` flow.
Between them the phone logged a cancelled LE connection attempt every ~8 min
(status `0x02`), which is Android's background auto-connect being restarted,
not watch activity.

Another one in capture 3 at 14:24:48, 56 s after a completed `04` manual sync
and 14 s before the watch entered Location Indicator mode: same pattern (CCCD +
MTU, no `22`, watch drops ~7 s later, `0x13`), plus the phone's own GATT server
sent the watch a Service Changed indication (`h0003`, `01 00 ff ff`) — so the
watch also connects as a GATT *client* to the phone.

### CURRENT_TIME (`0x09`) — identical to GBD-200

```
09 ea07 09 0b 14 02 26 05 d7 01
   year=2026 LE, month, day, hour, min, sec (binary, local time), dow (Sun=0, here Fri=5),
   fractions256, reason (1 = sync)
```

### GPS chunks (`0x24`) — layout as GBD-200, meaning differs

```
24 <slot> 01 <lat float64 BE> <lon float64 BE> 04
```

- Slot `00` = **the phone's current GPS position at sync time** (the home city is
  GPS-paired). It moved with the phone across capture 2: 39.2181/9.1820 at
  20:02 (Poetto seafront), 39.2207/9.2525 at 20:14 (Via Lipari), 39.2182/9.2670
  at 06:30 (home, the same value as throughout capture 1).
- Slot `01` = world-time city coordinates, constant for a given city: Amsterdam
  (52.37, 4.90) and London (51.51, −0.126) in capture 1, London in capture 2.

(On the GBD-200 the second chunk carried altitude instead.)

---

## Status block (`0x05`, param `0x1c`) (?)

Fetched during `01` and `03` connections, on CONVOY only:

```
cap 1, 09-09 16:16:  26 09 09 14 10  00 00 01 00 01 01 00 00 00 fe 00×11 19 00
cap 2, 09-12 06:30:  26 09 11 06 30  04 04 02 01 00 00 00 00 00 19 19 19 00×9 19 00
cap 3, 09-14 06:30:  26 09 13 06 30  04 04 00 00 00 00 00 00 00 19 19 19 00×9 19 00
cap 3, 09-14 14:19:  26 09 14 06 30  00 00 00 00 02 02 00 00 00 19 00×9 00 19 00
```

Starts with a BCD `yy mm dd hh mm` timestamp in **local** time. Three of the
four samples equal the most recent scheduled automatic time adjustment *before*
the current connection (both 06:30 fetches name the previous day's 06:30 slot;
the 14:19 fetch names that morning's 06:30) — so most likely "last successful
scheduled time adjustment". Capture 1's `14:10` still fits no known slot (the
app's history listed 12:30 that day). Trailing `19 00` = 25 again, and
`19 19 19` at [14:17] in two samples (cf. `28 19 19 00`). Otherwise undecoded.

---

## NEW_DATA status (`0x37`)

Read via ALL_REQ after init. Tells the app whether the watch holds unsynced
mission-log data:

```
37 00 ffffffffffff                  # nothing pending (also right after a day rollover:
                                    #   it does NOT flag pending LIFE LOG history)
37 01 ffffffffffff                  # new mission-log record(s) pending (START pressed)
37 02 ffffffffffff                  # mission running, altitude series data pending
37 03 26 09 11 18 14 18             # record(s) + series + location point, BCD UTC ts
```

Byte[1] is a flags field: `0x01` = mission-log record(s), `0x02` = mission-log
series/point data. Observed: `37 01` right after mission START (cap 1 video
7:20, cap 2 20:02:52, cap 3 10:14:07); `37 02` (timestamp still `ff`) at every
hourly offload connection during capture 3's 4-hour mission (at 11:12, 12:12,
13:13 and 14:12 local); `37 03` with the timestamp of the GOAL press
(14:24:45 UTC in cap 1, 18:14:18 UTC in cap 2, 12:19:19 UTC in cap 3).
Pressing GOAL on the watch is what saves the location point.

---

## Mission log block (`0x19` on DATA_REQ_SP)

```
phone → h0011  00 19 00 00 00
watch → h0011  00 19 26 01 00 00 00            # 0x0126 = 294 bytes follow
watch → h0014  <294 bytes over 2 notifications, not XOR'd>
phone → h0011  04 19 00 00 00
```

Layout of the 294-byte payload (all timestamps BCD, UTC):

```
[0:6]     series header: yy mm dd hh mm (BCD, minute resolution) + sample count
          ff ff ff ff ff 00 when no series is stored
          e.g. 26 09 11 18 03 06 = series starting 2026-09-11 18:03 UTC, 6 samples
[6:126]   60 × LE16 signed altitude samples in metres, 0x7fff = empty —
          the auto-measured altitude series of the most recent mission
[126:294] 14 × 12-byte event records, oldest first:
            [0:2]   altitude, metres LE16 signed (0xffff = -1; measurement failed?)
            [2:8]   yy mm dd hh mm ss (BCD, UTC)
            [8:12]  ff 04 04 ff
          empty record slot: ff7f ffffffffff fe ffffffff
```

Semantics established across the two captures:

- Records come in **pairs: S at mission START, G at GOAL**. G is the same button
  press that saves the location point (`37` bit `0x02`). The record altitude is
  the current auto-measured altitude (S = first series sample, G = last).
- The **record area is a 14-entry FIFO**: once full, each new record evicts the
  oldest. Capture 1 ended exactly full (14 records); the 20:02 fetch of capture 2
  had dropped `260906123548` and appended S `260911180249`, the 20:14 fetch had
  dropped `260906123631` and appended G `260911181419`. Records are *not*
  cleared by the ACK — the same 14 were still there at 06:30 the next day.
- The **series is cleared by the ACK**: present (6 samples) at 20:14, gone
  (`ff ff ff ff ff 00`, all `7fff`) at 06:30 with nothing recorded in between.
- Sampling: first sample at START (minute resolution), then every 2 min with
  `2f` bit `0x04` set — the 20:02:49→20:14:19 mission gave samples at 18:03,
  :05, :07, :09, :11, :13 UTC = 6 (−19, −19, −18, −17, −14, −6 m; barometric,
  hence below sea level on the beach). Capture 1's 87 s mission gave 1 sample.
- The S record is delivered in the connection the watch opens at START (reason
  `08`), the G record plus the series in the one it opens at GOAL. At START the
  app posts a notification "CASIO WATCHES · Calcolo in corso…" (it is taking a
  GPS fix) and its foreground service then records the phone's GPS track until
  GOAL; the app's MISSION LOG map (S→G polyline) and the LOCATION POINT card
  are built from the **phone's** GPS, the watch contributes only altitude and
  timestamps. The app re-fetches the whole block each sync and diffs.
- **While a mission runs, the watch reconnects every hour** (capture 3: START
  10:14:05 local, then connections at 11:12, 12:12, 13:13 and 14:12, all reason
  `08`, all reporting `37 02`). Each runs the normal `08` flow, so the
  accumulated altitude series and LIFE LOG hourly bins are fetched and
  ACK-consumed mid-mission. This is how the advertised 12 h of logging fits
  into a 60-sample buffer: no paging via `00 19 xx xx xx` was ever needed or
  seen. (What happens when the phone is unreachable for > 2 h mid-mission —
  buffer wrap or sampling stop — is still unknown.)

Capture 3's mission (hiking, 08:14:05 → 12:19:20 UTC, 301 m down to 5 m) as the
app saw it:

```
08:14  START connection   37 01  series empty (2 s in), S record 2d01 260914081405
09:12  offload #1         37 02  series 26 09 14 08 14, 30 samples: 300 276 254 219 153 128 … 19
10:12  offload #2         37 02  series 26 09 14 09 14, 30 samples: 17 15 13 13 9 8 … 2
11:13  offload #3         37 02  series 26 09 14 10 14, 30 samples: 2 2 2 2 2 2 … 4
12:12  offload #4         37 02  series 26 09 14 11 14, 30 samples: 3 3 4 3 3 …
12:19  GOAL connection    37 03 26 09 14 12 19 19   series 26 09 14 12 14, 3 samples [5, 5, 5],
                                 G record 0500 260914121920
```

(times UTC; the connections are the local-time ones listed above). Each ACK
cleared the series, so every lap restarts from the next sample — at GOAL only
the 3 samples since the 12:12 offload were left. The 30-sample laps match the
2-min interval exactly (60 min), and the first sample of lap 1 (300 m) ≈ the S
record (301 m). The FIFO evicted `260906212830` for the S record and
`260906212858` for the G record, both as predicted.

Capture 2 record area at 20:14 (oldest first):

```
0300 260906140602   0400 260906160648    # two unpaired(?) taps, 3 m / 4 m
0000 260906212830 / 0000 260906212858    # sea level
ffff 260906215651 / ffff 260906220439    # altitude invalid
5a00 260908061611 / 5a00 260908061619    # 90 m
4001 260908071406 / 4001 260908071418    # 320 m
1a00 260909142318 / 1a00 260909142445    # capture 1's mission, 26 m
edff 260911180249 / faff 260911181419    # capture 2's mission: S 20:02:49, G 20:14:19 local
```

Capture 3's GOAL fetch then appends `2d01 260914081405` (S, 301 m) and
`0500 260914121920` (G, 5 m), evicting the two `2609062128xx` rows.

Open: 60 samples cover only 2 h at the 2-min interval (5 min at 5 s), while the
watch advertises 12 h / 1 h of logging. No paged requests via the three
parameter bytes of `00 19 xx xx xx` were ever seen — instead the watch offloads
hourly mid-mission (above). Whether the buffer wraps when it does fill
(phone unreachable mid-mission) is untested.

---

## LIFE LOG block (`0x11` on DATA_REQ_SP)

```
phone → h0011  00 11 00 00 00
watch → h0011  00 11 a0 00 00 00 00            # 0xa0 = 160 bytes
watch → h0014  <160 bytes, not XOR'd>
phone → h0011  04 11 00 00 00                  # ACK clears the history parts
```

Layout:

```
[0:48]     24 × LE16  steps per hour — one entry per hour *completed* since the
                      last ACKed fetch, most recent first, 0xfffe = empty
[48:96]    24 × LE16  kcal per hour, same indexing
[96:100]   LE32       steps today (live counter)
[100:104]  LE32       kcal today (watch's own estimate)
[104:160]  7 × (LE32 steps, LE32 kcal)  daily totals of previous days not yet
                      fetched, most recent first (?), 0xfffffffe = empty
```

Evidence (capture 2):

| Fetch | today steps / kcal | hourly steps | hourly kcal | history |
|-------|--------------------|--------------|-------------|---------|
| 11th 20:02:54 | 4172 / 1920 | 252, 269 | 104, 124 | — |
| 11th 20:14:23 | 4195 / 1929 | all empty | all empty | — |
| 12th 06:30:35 | 0 / 0 | 0×7, 197, 92, 311 | 0×7, 89, 38, 128 | 4772, 2175 |

The 20:14 fetch is empty because the 20:02 ACK consumed the two entries (18:xx
and 19:xx — the previous sync was at 18:30) and no hour had completed since.
At 06:30 the day had rolled over: today is 0, yesterday's final totals sit in
the history slots, and there are 10 hourly entries for the 10 hours completed
since 20:14 (20:xx … 05:xx). Their sums, 600 steps and 255 kcal, equal exactly
4772 − 4172 and 2175 − 1920, i.e. everything since the 20:02 fetch. Capture 1
behaves the same (two entries at 16:16, empty at 16:23 and 16:24).

Capture 3 tracks one day across seven fetches and confirms the model exactly
(hourly bins = completed hours since the last ACKed fetch, consumed by it):

| Fetch (14th) | today steps / kcal | hourly steps | hourly kcal | history |
|--------------|--------------------|--------------|-------------|---------|
| 06:30 (r=03) | 456 / 282 | 18, 0, 0, 0, 242, 196, 531, 67, 0, 27, 330, 143, 528, 147, 28, 137, 80, 0 | 9, 0, 0, 0, 104, 169, 279, 23, 0, 9, 272, 59, 215, 59, 10, 54, 40, 0 | 3491, 1605 (13th) |
| 10:14 (START) | 7224 / 4458 | 3366, 2584, 756, 0 | 2667, 1183, 299, 0 | — |
| 11:12 (offload) | 10042 / 5758 | 2218 | 1059 | — |
| 12:12 (offload) | 11479 / 6409 | 2099 | 919 | — |
| 13:13 (offload) | 12496 / 7045 | 874 | 581 | — |
| 14:12 (offload) | 13050 / 7280 | 505 | 208 | — |
| 14:19 (GOAL) | 13050 / 7280 | all empty | all empty | — |

Every hourly bin is accounted for: 456 (06:30) + 6706 (four bins at 10:14) +
2218 + 2099 + 874 + 505 ≈ the 13050 final total, the remainder being the
still-open hours' steps at each fetch. The 14:19 fetch is empty because the
14:12 offload had just consumed hour 13:xx. The ordering is **most recent
first**: at 10:14 the biggest bin (3366 steps) must be 09:xx — the user was
hiking uphill (START pressed at 10:14 at 301 m) — and the zero is 06:xx
(asleep), reading the list newest→oldest. Capture 2's overnight list also reads
more plausibly that way (311/92/197 steps in the evening 20–22 h, then nothing
overnight). The app's 4.172/4.195 step figures match the LE32 exactly, while
its kcal figure (1.569/1.585) is its own profile-based computation, not the
watch's value.

---

## Settings

All settings are single ALL_FEAT WRITE_REQs of the full feature block (the app
reads the block, flips bits, writes it back). Numbers are plain binary, not BCD.

### Alarms (`0x15` = alarm 1, `0x16` = alarms 2–5)

4 bytes per alarm: `[enable] [0x40] [hour] [minute]`, enable = `0x40` on / `0x00` off.
Byte[1] reads back as `0x00`; the app writes it as `0x40` (write-only flag (?)).

```
phone → ALL_REQ   15
watch → ALL_FEAT  15 00 00 0b 38                      # alarm1 11:56, off
phone → ALL_FEAT  15 40 40 0b 38                      # → 11:56, on
phone → ALL_REQ   16
watch → ALL_FEAT  16 [a2 4B][a3 4B][a4 4B][a5 4B]     # alarms 2–5
phone → ALL_FEAT  16 00400000 00400000 40400300 00400000   # alarm4 = 03:00 on
```

The "Segnale" (hourly chime) toggle was not exercised — flag location unknown.

### Countdown timer (`0x18`)

```
18 [hours] [minutes] [seconds] 00×11        # 15 bytes
```

Observed: `18 00 0b 00…` = 0:11:00, `18 00 0c 00…` = 0:12:00, `18 01 0c 00…` = 1:12:00.

### BASIC (`0x13`) — 12 bytes

```
13 <flagsA> <light_dur> 00 00 00 00 00 <flagsB> 00 00 00
```

- `flagsA` (byte[1], default `0x06`):
  - bit `0x01` — one of the three "Display orologio" switches, see below (?)
  - bit `0x02` — button tones enabled
  - bit `0x04` — auto light **disabled** (cleared = auto light on)
- `light_dur` (byte[2]): `0x00` = 1.5 s, `0x01` = 3 s
- `flagsB` (byte[8], default `0x0c`):
  - bit `0x04` — use air-pressure sensor for energy (kcal) calculation
  - bit `0x08` — compass auto-correction ("Impostazioni direzione")

### SENSOR/DISPLAY config (`0x2f`) — 6 bytes

```
2f <flags> <b2> 00 00 00
```

- bit `0x04` of `<flags>` — altitude auto-measurement interval: 1 = 2 min (12 h),
  0 = 5 s (1 h). Toggled alone (video 1 4:00 / 4:10) and confirmed by the
  mission-log series (2-min samples with the bit set).
- bit `0x08` of `<flags>` and `<b2>` (`04` default) — see below.

Default observed `2f 0c 04 00 00 00`.

**"Display orologio" switches (?)**: the app's display page has three settings
— 12 h / 24 h, "Modalità pressione" (Spostamenti pressione / sec) and
"Modalità dislivello" (sec / ±100 / ±1000). In capture 1 all three were flipped
at once (24 h + sec + sec, video 1 3:15) and sent as two writes:

```
13 07 00 … 0c …          # flagsA 06 → 07   (bit 0x01 set)
2f 04 00 00 00 00        # flags  0c → 04   (bit 0x08 cleared), b2 04 → 00
```

then restored together (`13 06`, `2f 0c 04`). Three fields changed for three
switches, so each field is one of them but the assignment is not determined;
toggle them one at a time to settle it (the earlier reading "bit 0x01 =
pressure graph, 2f bit 0x08 = altitude graph" was a guess).

### BLE_SETTINGS (`0x11`) — 15 bytes

```
11 0f 0f 0f 06 00 50 00 04 00 01 00 <a> 1e <t>
```

- `<a>` (byte[12]): bit `0x80` = automatic time sync **disabled**
- `<t>` (byte[14]): app connection timeout in minutes — observed 03 / 05 / 0a
  ("Tempo di connessione con l'app": 3/5/10 min)

### Mode & display customization (`0x38`) — 17 bytes, read/write

Backed by the app's "Personalizza Modalità" page, which has two tabs
(capture 3 video, where all four writes below were made):

```
38 [8 mode ids]  [8 screen slots]
38 01 02 03 04 05 06 07 08  03 07 08 01 05 ff ff ff     # default observed
```

- `[1:9]` — the **"Modalità" tab**: the 8 modes in carousel order, ids
  1–8 = BAROMETER, TEMPERATURE, RECALL, SUNRISE, STOPWATCH, TIMER, ALARM,
  WORLD TIME (the app lists them in this id order). Toggling a mode off
  removes its id and shifts the rest left, padding with `ff`
  (`01 02 03 04 05 06 07 ff` = WORLD TIME hidden). The app warns that hiding
  a mode disables its functions ("Esempio: la sveglia sarà disattivata").
- `[9:17]` — the **"Mostra" tab**: which timekeeping display screens the watch
  cycles through, in display order, `ff`-padded. Screen ids, mapped by their
  position in the app list (single capture, so positional mapping is assumed):
  `01` = "Giorno e data", `02` = "YEAR DATE", `03` = "Grafico Pressione
  Barometrica …" (first row, label truncated), `04` = "Grafico Pressione
  Barometrica", `05` = "ore / min / sec", `06` = "Ora Mondiale HH MM",
  `07` = "STEPS (TODAY)", `08` = "SUNRISE/SUNSET (TODAY)". Toggling a screen
  on appends its id at the first `ff`; toggling off removes + shifts + pads.

Writes are full-block WRITE_REQs, verified by the app with an immediate
re-read (capture 3, video 0:05–1:40):

```
38 … 03 07 08 01 05 02 04 06   # all 8 screens on
38 … 03 07 08 01 05 04 ff ff   # YEAR DATE and Ora Mondiale off again
38 01 02 03 04 05 06 07 ff …   # WORLD TIME mode hidden
38 01 02 03 04 05 06 07 08 …   # and back on — final state: default modes,
                               # 6 screens (03 07 08 01 05 04)
```

Only seen in the `01` flow. After the first `38` write of a session the app
also re-read `11` / `13` / `2f` before re-reading `38`. "Ripristina
Impostazioni" (restore defaults) was not exercised.

---

## World time / DST — `0x21` transactions

Any change touching cities or DST is wrapped in a `0x21` begin/end pair and
rewrites the whole city state (`1d`, `1e`, `24`, `1f`, `2f`), even unchanged parts:

```
phone → ALL_FEAT  21 00 <n>        # begin transaction
… reads + full rewrite of 1d / 1e×2 / 24×2 / 1f×2 / 2f …
phone → ALL_FEAT  21 01 <n>        # end transaction
```

Observed `<n>`: `01` = world-city change, `02` = home/world swap, `03` = DST
mode change. (Probably just an operation tag.)

### DST/city state (`0x1d`) — 15 bytes

```
1d 00 01 <dst_home> <dst_world> <city_home LE16> <city_world LE16> ff×6
```

- DST mode: `00` = off, `01` = on, `03` = auto
- City codes observed: home (Rome, GPS-paired) = `f5 76`, Amsterdam = `0a 00`
  (10), London = `a0 00` (160)

### DST setting slots (`0x1e`) — 7 bytes per slot

```
1e <slot> <city LE16> <utc_off> <dst_off> 02
```

Slot 0 = home, slot 1 = world city. Observed `f5 76 04 04 02` (Rome),
`0a 00 04 04 02` (Amsterdam), `a0 00 00 04 02` (London): byte[3] looks like the
UTC offset in 15-minute units (`04` = +1 h, `00` = UTC) and byte[4] the DST
amount (`04` = 1 h) **(?)**.

### City names (`0x1f`) — same as GBD-200

```
1f <slot> <ASCII city name, zero-padded to 18>
```

### Home/world swap (capture 1, video 4:52–5:24)

Transaction `n=02`: the app swaps every pair — `1d` city codes, both `1e` slots,
both `24` coordinate chunks, both `1f` names — and the watch's main display then
shows the former world city.

---

## Location Indicator (`0x35`) — live session

The watch's "Indicatore Posizione" (direction/distance to a saved location
point) is driven by the phone: the app computes distance and bearing from its
own GPS to the point and feeds them to the watch over a `07` connection.

### Packet format

```
watch → ALL_FEAT  35 <mode> 00 00 00 00 00 00 00      # state / poll
phone → ALL_FEAT  35 <mode> <st> <dist LE32> <bearing LE16>
```

- `<mode>`: `02` = watch is in Location Indicator mode, `00` = it is not
- `<st>`: `00` = payload valid / OK, `01` = nothing to give
- `<dist>` = distance to the point in metres, `<bearing>` = direction from the
  phone to the point in degrees (0–359, true north)

Verified with real geometry: the phone position written in `24 00` at 06:30
(home) to the one written at 20:14 (the point) computes to 1284 m at 282.5°;
while the phone sat at home the watch was fed 1281–1318 m at 282–283°.

### Session flow (capture 2, 20:14:50–20:21:17, video 12:44–17:16)

```
20:14:50  watch connects (r=07), phone → ALL_REQ 35
          watch → 35 00 00…                       # not in indicator mode yet
          phone → h0009 read, then 35 00 00 00…   # nothing to do
          watch drops 0.3 s later
20:15:00  watch connects (r=07), phone → ALL_REQ 35
          watch → 35 02 00…                       # indicator mode
          phone → h0009 read, then 35 02 00 00 00 00 00 00 00   # accept
          phone requests conn-param update; app dialog appears:
            "Indicatore Posizione operativo — questa funzione verrà disattivata
             quando la connessione con l'orologio sarà interrotta. Premi il
             pulsante CONNECT sull'orologio per estendere l'attivazione…"
20:15:13  watch → 35 02 00…   (poll)   phone → h0009, 35 02 00 00…  (all zeros)
20:15:24  watch → poll                 phone → 35 02 00 1f 00 00 00 ac 00   # 31 m, 172°
20:15:41  watch → poll                 phone → 35 02 01 00…                 # nothing
20:16:22  watch → poll (40 s later)    phone → 35 02 01 00…
20:16:32  watch drops; dialog closes
20:16:47  watch connects again (r=07) → 35 02 → phone 35 02 00 77 03 00 00 0c 01  # 887 m, 268°
          … polls every 10–20 s, answers 1168 m/272°, 1214 m/273°, 01, 01,
          1318 m/283°, 1289 m/283°, … 1287 m/283° (phone parked at home) …
20:21:17  watch drops after 4.5 min (video had ended; cause unknown)
```

The watch's poll interval is nominally 10 s but stretches to 20–40 s; the app
reads `h0009` before every answer. The session ends when the watch hangs up —
after a couple of `01` answers, or on its own after a few minutes **(?)** — and
pressing CONNECT on the watch opens a fresh `07` connection to continue.

`<st> = 01` in capture 1 was the answer to every `35 02` before any location
point existed (three connections at 16:22–16:23, the watch dropped each time
within 0.3 s), and to a `35 00` in the same state; the same `35 00` got `00` in
capture 2 once a point existed. Inside a session it appeared once between the
1 m and 21 m updates of capture 1, twice right after the phone passed the point
and twice as it arrived home in capture 2 — most likely "no fresh position
right now" **(?)**. In capture 3 (14:25:03 and 14:25:17, after the settings
session) the watch connected twice in indicator mode and got `35 02 01` both
times, then dropped within seconds — even though a location point had been
saved at 14:19; the phone presumably had no usable GPS fix (indoors), which
supports the "no fresh position" reading.

The saved point itself never travels over BLE as coordinates: the watch only
reports *when* it was saved (`37` timestamp = the G record) and the app keeps
the phone's GPS fix from that moment (the LOCATION POINT card).

---

## Feature `0x36` (?)

Seen only in the scheduled `03` connection, after the `2f` echo and an `h0009`
read, right before the time write (identical bytes in capture 2 and in capture
3's 06:30 sync — two observations):

```
phone → ALL_FEAT  36 00 01 08 00
watch → ALL_FEAT  36 00 01 00 00
```

Unknown. Neighbours `0x35`/`0x37` are Location Indicator / NEW_DATA; it was not
sent in the `01`, `04` or `08` flows.

---

## Differences from the GBD-200 at a glance

| Aspect | GBD-200 | GG-B100 |
|--------|---------|---------|
| GATT layout | 26eb…, handles h000c–h0018 | identical (minus NOTIF h0017) |
| CONVOY encoding | XOR 0xFF | plain, sentinel values |
| CONVOY handshake | ping / cap_set / init_sig / 09-07 signals | none — direct req/echo/ACK |
| Init | long, ends with watch `47 01` | short, ends with phone time write; flow chosen by the reason byte in `10` |
| Init extras | MODULE_ID 0x26, USER_PROF 0x45, `3d` resync | none; `0x05/1c` status, `0x37`, data fetches instead |
| `24` chunk 1 | altitude | world-city lat/lon (chunk 0 = live phone position) |
| Alarms/timer | not on 200 (watch-side only) | `0x15`/`0x16`/`0x18` |
| Fitness data | steps 0x11 + CONVOY sport sessions | LIFE LOG 0x11 (consumed on ACK) + mission log 0x19 (FIFO records + one series) |
| Settings style | per-feature echoes | read-modify-write bitfields in 0x13/0x2f/0x11 |
| Transactions | — | `0x21` begin/end around city/DST edits |
| Navigation | — | `0x35` Location Indicator (phone → distance/bearing) |

Shared and byte-identical: `0x09` time format, `0x1f` city names, `0x24` float64
BE coordinate encoding, `0x22` APP_INFO token semantics, DATA_REQ op codes
(`00` request / `04` ACK), and the CCCD toggling ritual around fetches.

## TODO — what to capture next

Each item lists the open question and what to record (HCI snoop on, plus a
screen recording of the app for correlation; note the exact time of every
watch button press):

- [ ] **Fresh pairing** — unpair the watch in the app, then re-pair with the
      snoop running. Answers: the full GATT table (the `h0009`=`0xfa` poll's
      UUID, anything beyond `h0015`), the first-pairing sequence (all captures
      start already-paired), how the APP_INFO token is set.
- [ ] **"Display orologio" switches, one at a time** — 12/24 h, "Modalità
      pressione", "Modalità dislivello": toggle each one separately with a send
      in between (capture 1 flipped all three at once, so the assignment of
      `13` bit `0x01`, `2f` bit `0x08` and `2f` byte[2] is undecided).
- [ ] **Hourly chime** — the "Segnale" toggle on the alarms page; the flag
      location is unknown (watch the `15`/`16`/`13` blocks).
- [ ] **`0x38` drag-reorder + defaults** — reorder modes and screens by
      dragging (only toggles were captured), and press "Ripristina
      Impostazioni" once.
- [ ] **Phone finder** — open the app's "Trova telefono" page (ringtone,
      volume, "Test del volume") and then trigger the search from the watch,
      once with the app open and once with it killed. (No notification settings
      exist in the app, so phone→watch notifications are most likely
      unsupported.)
- [ ] **Location Indicator with a GPS log** — walk outdoors with the indicator
      active, a known target point and a GPS track recording on the phone, to
      pin down `35` `<st>=01`.
- [ ] **Mission with the phone unreachable** — START a mission, keep Bluetooth
      off / the phone away for 3+ hours, then GOAL and sync. Answers: does the
      60-sample series wrap (header advance, count restart) or stop? Repeat in
      the 5-s interval mode if possible (advertised 1 h there).
- [ ] **LIFE LOG history depth** — skip all syncs for a few days (auto sync off,
      app killed), then one fetch: fills the 7 day-slots and settles their
      ordering.
- [ ] **A 12:30 or 18:30 scheduled sync** — all `03`-flow samples so far are
      06:30 ones; a midday/evening slot adds `0x36` and `0x05/1c` status-block
      samples and may explain capture 1's anomalous `14:10` status timestamp.
      Nothing to do actively — just keep the snoop on.

Resolved by capture 3: mission logs longer than the 60-sample buffer (hourly
offload connections), the `0x38` write format, the LIFE LOG hourly ordering
(most recent first), the `0x37` flags split.
