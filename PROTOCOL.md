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
| `0x20` | VERSION_INFO   | `0x3d` | BLE_PARAM     |
| `0x0a` | FIND_PHONE     | `0x43` | TARGET_VAL    |
| `0x47` | SVC_DISC       | `0x45` | USER_PROF     |
| `0x48` | SESSION_EVENT  | —      | —             |

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

- `payload[6]` — bitmask of used slots (inverted: 0=used); popcount = total sessions
- Sessions are stored newest-first at `SESSION_LIST_BASE + 0x40 + n`

### Session summary layout (186+ bytes, offset relative to payload[1])

| offset | field |
|--------|-------|
| +174   | duration_min, duration_sec |
| +176   | avg_pace_min, avg_pace_sec |
| +178   | kcal |
| +182   | cadence |
| +162   | track_addr LE16 |
| +166   | meta_addr LE16 |
| +142   | segment_count |
| +169   | dist_km float32 LE |
| +183   | lap pairs (min, sec) × seg_count |

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
```

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
watch → ALL_FEAT  43 …
phone → ALL_FEAT  43 …        # echo
phone → ALL_REQ   13          # BASIC
watch → ALL_FEAT  13 …
phone → ALL_FEAT  13 …        # echo
```
