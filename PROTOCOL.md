# Casio GBD-200 BLE Protocol

Reverse-engineered from btsnoop HCI captures and `probe_casio.py`.

---

## GATT Characteristics

| Name           | UUID (26eb…)  | ATT handle | Direction         |
|----------------|---------------|------------|-------------------|
| ALL_REQ        | `002c`        | `h000c`    | phone→watch (write no-rsp) |
| ALL_FEAT       | `002d`        | `h000e`    | phone→watch (write) + watch→phone (notify) |
| ALL_FEAT-CCC   | —             | `h000f`    | CCCD for ALL_FEAT |
| DATA_REQ_SP    | `0023`        | `h0011`    | phone→watch (write) + watch→phone (notify) |
| DATA_REQ-CCC   | —             | `h0012`    | CCCD for DATA_REQ_SP |
| CONVOY         | `0024`        | `h0014`    | phone→watch (write no-rsp) + watch→phone (notify) |
| CONVOY-CCC     | —             | `h0015`    | CCCD for CONVOY |
| NOTIF          | `0030`        | `h0017`    | phone→watch (write no-rsp) |
| NOTIF-CCC      | —             | `h0018`    | CCCD for NOTIF |

The full UUID base is `26ebXXXX-b012-49a8-b1f8-394fb2032b0f`.

---

## Feature IDs (ALL_FEAT / ALL_REQ byte[0])

| ID     | Name           | ID     | Name          |
|--------|----------------|--------|---------------|
| `0x09` | CURRENT_TIME   | `0x22` | APP_INFO      |
| `0x10` | BLE_FEATURES   | `0x23` | WATCH_NAME    |
| `0x11` | BLE_SETTINGS   | `0x24` | GPS           |
| `0x13` | BASIC          | `0x26` | MODULE_ID     |
| `0x1b` | —              | `0x28` | WATCH_COND    |
| `0x1c` | CONVOY_INIT    | `0x2f` | FEAT_2F       |
| `0x1d` | DST_WATCH      | `0x39` | TIME_REQ      |
| `0x1e` | DST_SETTING    | `0x3a` | CONN_PARAM    |
| `0x1f` | WORLD_CITY     | `0x3b` | ADV_PARAM     |
| `0x20` | VERSION_INFO † | `0x3d` | BLE_PARAM     |
| `0x0a` | FIND_PHONE     | `0x43` | TARGET_VAL    |
| `0x47` | SVC_DISC       | `0x45` | USER_PROF     |
| `0x48` | SESSION_EVENT  | `0x3f` | RUN_ALERTS    |
| `0x40` | RUN_CONFIG     | —      | —             |

Also observed but undecoded (GBD-200, official app 2026-07-18): `0x25` (7-byte write on
reconnect, `25 18 18 17 20 01 01`), `0x5a` (requested once during init, no reply captured),
`0x3d` BLE_PARAM spontaneous notifications (`3d 20 00 02 01 00 03 03 2f 28 00 28 00 28 00 fa 00`).

† Feature `0x20` doubles as the per-lap **META_BLOCK** in the sport CONVOY context (addr = `meta_addr` from session summary).  Features `0x1d` (session list), `0x1e` (session summary), and `0x1f` (GPS track block) are also reused in the sport CONVOY context with different semantics from their ALL_REQ counterparts.

### ALL_REQ read request format

```
[feat_id]                      # simple 1-byte read request (most features)
[feat_id] [slot]               # slotted features (WORLD_CITY, DST_SETTING)
```

### ALL_FEAT data request format (DATA_REQ_SP / CONVOY)

```
[op] [feat] 00 [off_lo] [off_hi] 00 00 [param] 00 00
```
- op `0x00` = request, `0x04` = ACK, `0x03` = cancel

---

## Phase 0 — Init Handshake

Performed once per BLE connection. Watch shows "connection ok" only after this completes.

```
phone → ALL_REQ   0x22                         # request APP_INFO
watch → ALL_FEAT  22 …                         # APP_INFO reply
phone → ALL_REQ   0x10                         # request BLE_FEATURES
watch → ALL_FEAT  10 …
phone → ALL_FEAT  23 "CASIO GBD-200\0…"       # WRITE_REQ — identity confirm
phone → ALL_REQ   0x26                         # request MODULE_ID
watch → ALL_FEAT  26 …
# repeated twice:
phone → ALL_REQ   0x28 / 0x20                  # WATCH_COND, VER_INFO
watch → ALL_FEAT  28 … / 20 …
phone → ALL_REQ   0x28                         # final WATCH_COND
watch → ALL_FEAT  28 …
phone → ALL_REQ   0x1d                         # request DST_WATCH_STATE
watch → ALL_FEAT  1d …
phone → ALL_FEAT  1d …                         # echo it back (WRITE_REQ)
phone → ALL_REQ   0x1e                         # request DST_SETTING slot 0
watch → ALL_FEAT  1e …
phone → ALL_REQ   0x1e                         # request DST_SETTING slot 1
watch → ALL_FEAT  1e …
phone → ALL_FEAT  1e …                         # echo slot 0
phone → ALL_FEAT  1e …                         # echo slot 1
phone → ALL_FEAT  24 00 01 <lat_f64_BE 8B> <lon_f64_BE 8B> 04   # GPS lat/lon
phone → ALL_FEAT  24 01 01 <alt_f64_BE 8B> 00…                   # GPS altitude
phone → ALL_REQ   1f 00                        # WORLD_CITY slot 0
watch → ALL_FEAT  1f …
phone → ALL_REQ   1f 01                        # WORLD_CITY slot 1
watch → ALL_FEAT  1f …
phone → ALL_FEAT  1f …                         # echo slot 0
phone → ALL_FEAT  1f …                         # echo slot 1
phone → ALL_REQ   0x2f                         # FEAT_2F
watch → ALL_FEAT  2f …
phone → ALL_FEAT  2f …                         # echo
phone → ALL_REQ   0x45                         # USER_PROF
watch → ALL_FEAT  45 …
phone → ALL_FEAT  45 …                         # echo
phone → ALL_FEAT  09 <year_lo> <year_hi> <mon> <day> <hh> <mm> <ss> <dow> 00 01   # CURRENT_TIME
watch → ALL_FEAT  47 01                        # INITIALIZED ✓
# post-init:
phone → ALL_REQ   28 / 13 / 20 / 28           # WATCH_COND, BASIC, VER_INFO, WATCH_COND
```

### GPS chunk encoding

```python
c0 = b'\x24\x00\x01' + struct.pack('>d', lat) + struct.pack('>d', lon) + b'\x04'
c1 = b'\x24\x01\x01' + struct.pack('>d', alt) + b'\x00' * 9
```

### CURRENT_TIME encoding

```
09  year_lo year_hi  month  day  hour  min  sec  dow  fractions256  reason
```
- `dow`: Sunday=0 … Saturday=6
- `reason`: 1 = manual sync

---

## Steps Fetch

Uses DATA_REQ_SP (h0011) + CONVOY (h0014). CONVOY payload is XOR'd with `0xFF`.

```
phone → h0011  00 11 00 00 00         # request steps
watch → h0011  00 11 <len_lo> <len_hi> …
watch → h0014  <raw XOR-0xFF payload>
# decode: data = bytes(~b & 0xff for b in raw)
# data layout (after XOR):
#   [0:2]   payload_len LE16
#   [2]     year - 2000
#   [3]     month
#   [4]     day
#   [5]     hour
#   [6]     minute
#   [7:11]  steps LE32 (0xFFFFFFFE → 0)
#   [11:13] calories LE16 (0xFFFE → 0)
#   [13:15] birth_year LE16
#   [15]    birth_month
#   [16]    birth_day
#   [17]    0x00 → hourly history follows
#   [18+]   blocks: dtype(1) + block_len_LE16(2) + LE16 counts…
#           dtype 0x04=steps, 0x05=calories
phone → h0011  04 11 00 00 00         # ACK
```

---

## Sport Fetch (CONVOY handshake)

Uses h0011 (DATA_REQ_SP) and h0014 (CONVOY). Takes ~8–12 s; watch loads flash during this time.

```
phone → h0011  00 1c 00 00 00 00 00 00 00 00   # CONVOY_INIT request
phone → h0014  00 00 00                         # ping
watch → h0014  00 00 04                         # ping echo (ready)
             # or 00 01 04 = BUSY — see below
# wait up to 12s:
watch → h0011  00 1c …                          # h0011 echo (watch loaded flash)
phone → h0014  04 00 00 00 00 00 00 00 00 00   # cap_query
watch → h0014  04 …                             # cap_response
phone → h0014  04 01 18 00 18 00 00 00 dc 05   # cap_set
watch → h0014  04 …                             # cap_confirm
phone → h0014  06 00 00 00 00 00 00 00 00 00 00 00 00 00   # init_sig
watch → h0014  06 …                             # version
phone → h0014  06 …                             # version echo

# Session list (feature 0x1d, base addr 0x46a0):
phone → h0011  00 1d 00 a0 46 00 00 01 00 00
watch → h0014  05 …  (repeating, XOR-encoded data, type=0x05)
watch → h0011  09 …  (DATA_READY signal)
phone → h0011  09 …  (echo)
phone → h0011  04 1d 00 …  (ACK 0x1d)

# Per-session summary (feature 0x1e, addr per list):
phone → h0011  00 1e 00 <addr_lo> <addr_hi> 00 00 01 00 00
watch → h0014  05 …  (summary data)
watch → h0011  09 …
phone → h0011  09 … / 04 1e …  (echo + ACK)

# Per-lap meta block (feature 0x20, meta_addr from summary; only if meta_addr != 0/0xffff):
phone → h0011  00 20 00 <meta_addr_lo> <meta_addr_hi> 00 00 01 00 00
watch → h0014  05 …  (meta block data)
watch → h0011  07 …  (DONE signal — 0x07, not 0x09)
phone → h0011  07 … / 04 20 …  (echo + ACK)

# Close (always use cancel, not ACK):
phone → h0011  03 1c 00 00 00 00 00 00 00 00
```

### CONVOY data encoding (sport, type=0x05)

```python
# byte[0] (type) is unchanged; bytes[1:] XOR'd with 0xFF
decoded = bytes([data[0]] + [b ^ 0xff for b in data[1:]])
payload  = decoded[3:]   # skip 3-byte CONVOY header
```

### Session list layout (after decoding, base=0x46a0+6)

- `payload[6..18]` — 13-byte bitmask of used slots (inverted: 0=used, 1=free).
  Bit `b` (LSB-first) of `payload[6+i]` = slot `i*8 + b`, for 104 slots total
  (matches the watch's ~100-run capacity); popcount of zero bits = total sessions
- Slots form a **ring buffer**: used slots need *not* be contiguous. Chronological
  order follows the slot index (wrapping at 104), with the free gap sitting between
  the newest and oldest sessions
- The summary for slot `b` lives at `SESSION_LIST_BASE + 0x41 + b` (feature `0x1e`) —
  fetch per set bit, not sequentially `1..N`
- A slot marked "used" can still contain erased flash (summary payload all-`0x00` or
  all-`0xff`). Filter these by BCD start-year sanity: erased slots decode to year 0
  (zeros) or ~16665 (`0xff` = BCD "165"); real sessions are 2000–2099

### Session summary layout (offset = direct index into `payload[]`, where `payload[0]` = `decoded[3]`)

| offset | field |
|--------|-------|
| +126   | record_stride LE16 (= 7) |
| +128   | unknown LE16 (= 19) |
| +130   | total_track_bytes LE32 (`record_count × 7`) |
| +134   | record_count LE16 |
| +138   | meta_lap_bytes LE16 (`seg_count × 19`) |
| +142   | segment_count |
| +147   | start_time — 7-byte BCD: `[year_lo, year_hi, month, day, hour, min, sec]` |
| +154   | end_time — 7-byte BCD: same format |
| +162   | track_addr LE16 — GPS track block start (feature `0x1f`) |
| +166   | meta_addr LE16 — per-lap meta block start (feature `0x20`) |
| +169   | dist_km float32 LE |
| +174   | duration_min, duration_sec |
| +176   | avg_pace_min, avg_pace_sec |
| +178   | kcal |
| +182   | cadence |

### Meta block (feature `0x20` @ `meta_addr`)

Contains per-lap records for one activity. Layout:

```
[0]     0x00
[1]     session_offset  (= session_addr − SESSION_LIST_BASE)
[2]     next_session_offset
[3]     0x00
[4:8]   0xff 0xff 0xff 0xff   (flash-erased padding)
[8:14]  0x00 × 6
[14]    0xff / 0xfe            (separator before first record)
[15:]   lap records × seg_count (19 bytes each, see below)
```

**19-byte lap record layout:**

| offset | size | field |
|--------|------|-------|
| 0–3    | 4    | `distance_km` — LE32 IEEE 754 float |
| 4      | 1    | — (0x00) |
| 5–6    | 2    | `elapsed_min`, `elapsed_sec` — cumulative time at lap end |
| 7      | 1    | — (0x00) |
| 8–9    | 2    | `lap_duration_min`, `lap_duration_sec` |
| 10–11  | 2    | `avg_pace_min`, `avg_pace_sec` (per km) |
| 12     | 1    | `calories` (kcal for this lap) |
| 13–15  | 3    | — (0x00 × 3) |
| 16     | 1    | `cadence` (spm) |
| 17     | 1    | — (0x00) |
| 18     | 1    | end marker (0xff or 0xfe) |

### BUSY recovery (ping echo = `00 01 04`)

```
phone → h0014  03 00          # cancel
phone → h0011  03 1c 00…     # cancel 0x1c
# wait for WATCH_COND 28 … with byte[7]==0x01 (ready)
# re-enable CCCDs, retry init + ping
```

---

## Main-Menu Resync (`3d 01`)

When the user navigates to the watch main menu, the watch sends `3d 01 …` on ALL_FEAT and resets its CCCD/CONVOY state. The phone must re-sync before the next sport/steps command.

```
watch → ALL_FEAT  3d 01 …     # BLE_PARAM: main menu entered
# required recovery:
  disable h0011/h0014 CCCDs
  enable  h0011/h0014 CCCDs
  phone → h0011  00 11 00 00 00   # steps fetch (warms up CONVOY state machine)
  wait   h0011  00 11 …
  phone → h0011  04 11 00 00 00   # ACK steps
  disable h0011/h0014 CCCDs
  enable  h0011/h0014 CCCDs
```

Skipping the steps fetch causes the h0011 echo to arrive ~3 s late (after cap_query), breaking the sport handshake.

---

## Notifications (h0017)

All bytes XOR'd with `0xFF`. Phone writes WRITE_CMD to UUID `26eb0030-…`.

```
packet layout (before XOR):
  [0:4]   notif_id LE32
  [4]     action: 0x00=add, 0x02=delete
  [5]     alert: 0x01=vibrate
  [6]     icon (0x0d = SNS)
  [7:22]  timestamp ASCII "YYYYMMDDThhmmss"
  [22+]   TLV fields, each: LE16 length + UTF-8 string
            sender / title / subtitle / message
```

Ping/keepalive (30 bytes, byte[4]=`0xFD` after XOR): only byte[0] carries sequence counter; rest zeros.

---

## Phone Finder (`0x0a`)

```
watch → ALL_FEAT  0a 02       # user activated phone finder on watch
phone → ALL_FEAT  0a 01       # ACK (WRITE_REQ)
```

---

## Running Session Events (`0x48`)

```
watch → ALL_FEAT  48 00       # running session started
phone → ALL_FEAT  48 03 00 c8 00 14 0a 00 00 34 01 40 01 01 00 dc 05   # session ACK/config
# periodically during session:
phone → ALL_FEAT  48 05 00 c8 00 14 0a <elapsed_s> 00 34 01 40 01 01 00 dc 05
watch → ALL_FEAT  48 01       # running session ended

# After the user saves or discards the session on the watch (supposition):
watch → ALL_FEAT  28 06 <slot> 00 00 ba 01 <saved> <flags>
```

Post-session `0x28` fields (observed, not confirmed):
- `byte[2]` (`slot`): flash slot index — stays at current value if discarded, advances by 1 if saved
- `byte[7]` (`saved`): `0x00` = session discarded, `0x01` = session saved to flash
- `byte[8]` (`flags`): `0x00` if discarded, `0x04` if saved (possibly a "new data available" flag)

`48 03` / `48 05` constant fields:
- `c8 00` (LE16) = 200 — GPS rate / interval
- `14` = 20, `0a` = 10 — thresholds (unknown)
- `34 01` (LE16) = 308 — target pace (s/km, ~5:08/km)
- `40 01` (LE16) = 320 — target step count
- `dc 05` (LE16) = 1500 — target distance (m)
- byte[7] in `48 05` = elapsed seconds since session start

GPS location is sent during init (`0x24` chunks), not during the session.

---

## Config Sync

After init, or to clear "connection failed" on the watch face:

```
phone → ALL_REQ   45          # USER_PROF
watch → ALL_FEAT  45 …
phone → ALL_FEAT  45 …        # echo
phone → ALL_REQ   43          # TARGET_VAL
watch → ALL_FEAT  43 …        # two responses: sub-type 0x40 then 0x34
phone → ALL_FEAT  43 …        # echo each (may include accumulated data)
phone → ALL_REQ   13          # BASIC
watch → ALL_FEAT  13 …
phone → ALL_FEAT  13 …        # echo
```

### TARGET_VAL (0x43) exchange

Two request/response cycles occur in sequence:

```
phone → ALL_REQ   43              # first request
watch → ALL_FEAT  43 40 …         # sub-type 0x40 reply
phone → ALL_FEAT  43 34 … [kcal] … [goals]   # echo, phone adds kcal goal
phone → ALL_REQ   43              # second request
watch → ALL_FEAT  43 34 …         # sub-type 0x34 reply
phone → ALL_FEAT  43 34 … [daily_km] …        # echo, phone adds daily km goal
```

### TARGET_VAL (0x43) layout (15 bytes)

```
[0]      feature id = 0x43
[1:3]    LE16 — daily step goal          (e.g. 0x2134 = 8500 steps/day)
         (sub 0x40 carries a different value; sub 0x34 carries the goal)
[3]      0x00
[4:6]    LE16 — daily kcal goal          (e.g. 0x08fc = 2300 kcal/day)
         phone→watch only; watch returns 0x0000
[6:8]    LE16 — monthly distance goal, unit = 100 m  (e.g. 0x012c = 300 = 30 km)
[8]      0x00
[9:11]   LE16 — monthly time goal, unit = minutes    (e.g. 0x0168 = 360 = 6 h)
[11:13]  LE16 — daily distance goal, unit = 5 m      (e.g. 0x03e8 = 1000 = 5 km)
         second phone→watch echo only; watch returns 0x0000
[13]     0x00
[14]     goal display selector for the watch face (observed 2026-07-18, GBD-200:
         0x01 = "time attained"; other values unobserved — NOT always 0x0000)
```

Observed live example (GBD-200, official app, monthly goals 100 mi / 30 h, daily kcal 1):
`43 40 1f 00 01 00 4a 06 00 08 07 00 00 00 01` — `4a06`=1610×100 m ≈ 100 mi,
`0807`=1800 min = 30 h, `[4:6]`=`0100`=1 kcal, `[14]`=`01` = display "time attained".

---

## Run Settings (`0x3f` / `0x40`) and `0x2f` — GBD-200

Captured 2026-07-18 (GBD-200 + official app, one labeled toggle per sync; each phone
write is followed by an ALL_REQ read-back of the same feature). These writes are BARE
feature writes — no `0x21` settings bracket anywhere in the session.

### RUN_ALERTS (`0x3f`, 13 bytes) — four alert slots

```
3f [a1_flags][a1_interval LE16] [a2_flags][a2_interval LE16]
   [energy_flags][energy_interval LE16] [a4_flags][a4_interval LE16]
```

- flags per slot: `00` = off, `01` = on, `02` = on + auto-repeat
- slots 1–2: elapsed-time alerts, interval in minutes; slot 3: energy alert, interval
  in kcal; slot 4: unobserved-enabled (presumed distance alert, default interval 100)

```
21:31  3f 02 3c00 01 1e00 01 6400 00 6400   # A1 on+rep 60min, A2 on 30min, E on 100kcal
21:33  3f 02 3c00 00 1e00 01 6400 00 6400   # only change: A2 disabled (01→00)
```

### RUN_CONFIG (`0x40`, 6 bytes) — auto lap / auto pause / lap face

```
40 [flags] [autolap_dist LE16, 0.1-unit steps] [0xf7 ?] [lap_face]
```

- flags: bit `0x01` = auto lap, bit `0x02` = auto pause; bits `0x0c` always set (unknown)
- autolap_dist in 0.1 of the watch's current distance unit (`0a00` = 1.0 mi while in miles)
- byte[4] constant `0xf7` (unknown); byte[5] lap face preset: `00` = Set 1, `01` = Set 2

```
21:34  40 0f 0a00 f7 01   # auto lap ON 1.0mi, pause ON, face Set 2
21:35  40 0d 0a00 f7 01   # auto pause OFF   (bit 0x02 cleared)
21:37  40 0e 0a00 f7 01   # auto lap OFF     (bit 0x01 cleared)
21:38  40 0f 0a00 f7 00   # lap face → Set 1 (byte[5])
```

The watch may notify `0x40` spontaneously (observed once, unrequested).

### FEAT_2F (`0x2f`, 6 bytes) — settings-state / dirty flags / unit

```
2f [b1] 04 02 [b4] 00
```

- bit `0x02` of BOTH `b1` and `b4`: "settings changed on watch" dirty flags. Set by the
  watch after on-watch menu changes (watch-side changes are NOT notified live — they
  surface on the next `0x2f` poll). The official app then shows its "settings have been
  changed" alert and clears the bits by writing `b1`/`b4` with `0x02` unset. App-wins:
  the push overwrites the watch-side change.
- `b4` bit `0x08`: **NOT the distance unit** (hypothesis tested and falsified 2026-07-18:
  a watch verified to be in miles reported `2f 0c 04 02 16 00` — `0x08` clear, dirty bit
  set). Meaning unknown; the app changed it `1c → 14` between two full pushes.
- The distance unit's location remains unknown. Prime suspect: feature `0x25`
  (`25 18 18 17 20 01 01`), written only in the full push after which the watch switched
  to km — a display/format-shaped block (untested). `0x13` BASIC has only ever been
  observed with the watch in miles (`13 46 01 00…00 02`), so not fully excluded.
- remaining bits of `b1`/`b4` unknown — read-modify-write only.

```
21:49  watch → 2f 0e 04 02 1e 00   # after on-watch unit flips: dirty bits + 0x08 set
21:49  phone → 2f 0c 04 02 1c 00   # app clears dirty bits (unit still miles)
21:52  phone → 2f 0c 04 02 14 00   # full push after app profile → metric; watch now km
```

### Failed-push recovery

A settings push that fails mid-transfer ("transmission error" in the app — e.g. the watch
sitting in its own settings menu) is retried as: disconnect → reconnect → full init →
re-push of every settings block (`1d/1e/1f/24/2f/43/13/45` echoes + `25` + `09`).
