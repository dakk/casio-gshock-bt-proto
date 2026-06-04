#!/usr/bin/env python3
"""
Interactive probe for the Casio GBD-200 BLE protocol.

Usage:  python3 probe_casio.py [MAC]

Commands:
  steps                     Fetch step count and hourly history
  sport                     Fetch all sport activity sessions
  notify [msg]              Send a notification (message text)
  notify sender|title|msg   Send with explicit sender, title, message
  time                      Resend current time to watch
  raw <hexbytes>            Write raw hex to DATA_REQUEST_SP (e.g. raw 00 1d 00 ..)
  help                      Show this help
  quit / exit               Disconnect and exit
"""
import asyncio, sys, time, struct, datetime
from bleak import BleakClient

ADDR = sys.argv[1] if len(sys.argv) > 1 else "D1:3C:8F:15:D6:34"

# Created in main(); serialises concurrent handle_main_menu_resync callers.
_resync_lock = None

# ── Characteristic UUIDs ──────────────────────────────────────────────────────
UUID_ALL_FEAT = "26eb002d-b012-49a8-b1f8-394fb2032b0f"  # ALL_FEATURES (write + notify)
UUID_ALL_REQ  = "26eb002c-b012-49a8-b1f8-394fb2032b0f"  # READ_REQUEST_FOR_ALL_FEATURES
UUID_DATA_REQ = "26eb0023-b012-49a8-b1f8-394fb2032b0f"  # DATA_REQUEST_SP (h0011)
UUID_CONVOY   = "26eb0024-b012-49a8-b1f8-394fb2032b0f"  # CONVOY (h0014)
UUID_NOTIF    = "26eb0030-b012-49a8-b1f8-394fb2032b0f"  # NOTIFICATION

SESSION_LIST_BASE   = 0x46a0
TRACK_BLOCK_HDR    = 15   # 15-byte block header; bytes[5:7] = LE16 next-block addr
META_BLOCK_HDR     = 15   # 15-byte header (incl. separator at [14]); laps at [15:]
META_LAP_STRIDE    = 19   # bytes per per-lap record in meta block
TRACK_RECORD_STRIDE = 7
TRACK_BLOCK_LAST   = 0xffff

# Feature IDs (from Casio2C2DSupport)
FEAT_WATCH_NAME   = 0x23
FEAT_APP_INFO     = 0x22
FEAT_BLE_FEATURES = 0x10
FEAT_BLE_SETTINGS = 0x11
FEAT_VERSION_INFO = 0x20
FEAT_MODULE_ID    = 0x26
FEAT_WATCH_COND   = 0x28
FEAT_DST_WATCH    = 0x1d
FEAT_DST_SETTING  = 0x1e
FEAT_WORLD_CITY   = 0x1f
FEAT_GPS          = 0x24
FEAT_FEAT_2F      = 0x2f
FEAT_USER_PROF    = 0x45
FEAT_TARGET_VAL   = 0x43
FEAT_CONN_PARAM   = 0x3a
FEAT_ADVERT_PARAM = 0x3b
FEAT_BLE_PARAM    = 0x3d  # sent by watch on main menu entry; echo with page 0x30
FEAT_BASIC        = 0x13
FEAT_SVC_DISC     = 0x47
FEAT_CURRENT_TIME = 0x09

GPS_LAT = 40.21821986316132   # degrees N
GPS_LON = 10.26722141233894    # degrees E
GPS_ALT = 55.5                # metres

def make_gps_chunks(lat, lon, alt):
    c0 = bytes([0x24, 0x00, 0x01]) + struct.pack('>d', lat) + struct.pack('>d', lon) + bytes([0x04])
    c1 = bytes([0x24, 0x01, 0x01]) + struct.pack('>d', alt) + bytes(9)
    return c0, c1

GPS_CHUNK_0, GPS_CHUNK_1 = make_gps_chunks(GPS_LAT, GPS_LON, GPS_ALT)

# Step count data type IDs (from CasioConstants)
DATATYPE_STEPS    = 0x04
DATATYPE_CALORIES = 0x05

def xd(b): return ' '.join(f'{x:02x}' for x in b)

def xor_all(data):
    """XOR every byte with 0xFF (used for step count CONVOY data)."""
    return bytes(~b & 0xff for b in data)

def xor_payload(data):
    """XOR bytes[1:] with 0xFF, leave byte[0] (type) unchanged (used for sport CONVOY data)."""
    out = bytearray(data)
    for i in range(1, len(out)):
        out[i] ^= 0xff
    return bytes(out)

def feat_req(feat, offset=0, param=0):
    return bytes([0x00, feat, 0x00,
                  offset & 0xff, (offset >> 8) & 0xff,
                  0x00, 0x00, param, 0x00, 0x00])

def ack(feat):
    return bytes([0x04, feat] + [0x00] * 8)

def echo10(data):
    buf = bytearray(10)
    buf[:min(len(data), 10)] = data[:10]
    return bytes(buf)

# ── Notification queues ───────────────────────────────────────────────────────
all_feat_q = asyncio.Queue()
h0011_q    = asyncio.Queue()
h0014_q    = asyncio.Queue()
convoy_buf = bytearray()
convoy_collecting = False

# Set when the watch sends '3d 01 ...' (user navigated to main menu).
# The watch resets its CCCD state and expects a re-sync before accepting
# any sport/steps requests.  See handle_main_menu_resync().
_main_menu_event = False

# Global client reference so BLE callbacks can schedule async writes.
_g_client = None

# Fired by the Bleak disconnected_callback; lets the REPL detect drop-outs.
_disconnect_event = asyncio.Event()

def _on_disconnect(_client):
    print("\r  [!] Watch disconnected")
    _disconnect_event.set()

def _reset_queues():
    global all_feat_q, h0011_q, h0014_q, convoy_buf, convoy_collecting
    for q in (all_feat_q, h0011_q, h0014_q):
        while not q.empty():
            q.get_nowait()
    convoy_buf = bytearray()
    convoy_collecting = False

def cb_all_feat(_, data):
    global _main_menu_event
    data = bytes(data)
    print(f"\r  [allFeat←] feat=0x{data[0]:02x} {len(data)}B  {xd(data[:16])}{'…' if len(data)>16 else ''}")
    if data[0] == FEAT_BLE_PARAM and len(data) > 1 and data[1] == 0x01:
        _main_menu_event = True
        print("  [!] Watch entered main menu — CCCDs will be re-enabled before next command")
    if data[0] == 0x0a and len(data) > 1 and data[1] == 0x02:
        print("\r  [!] Your watch is searching for you!")
    if data[0] == 0x48 and len(data) > 1:
        if data[1] == 0x00:
            print("\r  [!] Running session started on watch")
        elif data[1] == 0x01:
            print("\r  [!] Running session ended on watch")
    if data[0] == 0x28 and len(data) >= 9 and data[1] == 0x06:
        if data[7] == 0x01:
            print("\r  [!] Session saved to flash (slot 0x{:02x})".format(data[2]))
        elif data[7] == 0x00:
            print("\r  [!] Session discarded")
    all_feat_q.put_nowait(data)

def cb_h0011(_, data):
    data = bytes(data)
    print(f"\r  [h0011←] {xd(data)}")
    h0011_q.put_nowait(data)

def cb_h0014(_, data):
    global convoy_buf, convoy_collecting
    data = bytes(data)
    ct = data[0]
    print(f"\r  [h0014←] type=0x{ct:02x} {len(data)}B  {xd(data[:24])}{'…' if len(data)>24 else ''}")
    if ct == 0x05 and convoy_collecting:
        dec = xor_payload(data)
        convoy_buf.extend(dec[3:])
    h0014_q.put_nowait(data)

async def w_all(client, data, lbl=""):
    print(f"  [allFeat→] {xd(data)}  {lbl}")
    await client.write_gatt_char(UUID_ALL_FEAT, data, response=True)

async def w_req(client, data, lbl=""):
    print(f"  [allReq→] {xd(data)}  {lbl}")
    await client.write_gatt_char(UUID_ALL_REQ, data, response=False)

async def w11(client, data, lbl=""):
    print(f"  [h0011→] {xd(data)}  {lbl}")
    await client.write_gatt_char(UUID_DATA_REQ, data, response=True)

async def w14(client, data, lbl=""):
    print(f"  [h0014→] {xd(data)}  {lbl}")
    await client.write_gatt_char(UUID_CONVOY, data, response=False)

async def drain(q):
    while not q.empty():
        q.get_nowait()

async def wait_for(q, pred, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            pkt = await asyncio.wait_for(q.get(), timeout=deadline - time.time())
            if pred(pkt):
                return pkt
        except asyncio.TimeoutError:
            break
    return None

# ── Phase 0: Init handshake (full-setup path, confirmed from logs_6 pkt 303-676) ──
async def init_handshake(client):
    """
    Full setup handshake confirmed from logs_6/BT_HCI_2026_0502_160843_UTC+0200.cfa.curf
    packets 303-676.  This is the sequence the watch expects to show "connection ok".

    Sequence:
      1.  Request APP_INFO (0x22)
      2.  Request BLE_FEAT (0x10)
      3.  Write WATCH_NAME to ALL_FEAT (WRITE_REQ, identity confirm)
      4.  Request MODULE_ID (0x26)
      5.  WATCH_COND + VER_INFO × 2, then one final WATCH_COND
      6.  Request DST_WATCH_STATE (0x1d) → echo back (WRITE_REQ)
      7.  Request DST_SETTING slot 0 (0x1e) → save
          Request DST_SETTING slot 1 (0x1e) → echo slot 0, echo slot 1
      8.  Write GPS chunk 0 and chunk 1 (0x24, WRITE_REQ, no request first)
      9.  Request WORLD_CITY slot 0 (0x1f 00) → save
          Request WORLD_CITY slot 1 (0x1f 01) → echo slot 0, echo slot 1
      10. Request FEAT_2F (0x2f) → echo back
      11. Request USER_PROF (0x45) → echo back
      12. Write CURRENT_TIME (0x09)
      13. Watch sends 47 01 → INITIALIZED
      14. Post-init reads: WATCH_COND, BASIC (0x13), VER_INFO, WATCH_COND
    """
    print("=== PHASE 0: INIT HANDSHAKE (full-setup path) ===")
    await client.start_notify(UUID_ALL_FEAT, cb_all_feat)
    await asyncio.sleep(0.1)
    await drain(all_feat_q)

    async def req_wait(feat_byte, label, req_payload=None, timeout=5):
        payload = req_payload if req_payload is not None else bytes([feat_byte])
        await w_req(client, payload, label)
        return await wait_for(all_feat_q, lambda d: d[0] == feat_byte, timeout=timeout)

    # 1. Request APP_INFO
    pkt = await req_wait(FEAT_APP_INFO, "request APP_INFO")
    if pkt is None:
        print("  TIMEOUT: APP_INFO"); return False
    print(f"  App info: {xd(pkt)}")

    # 2. Request BLE_FEAT
    pkt = await req_wait(FEAT_BLE_FEATURES, "request BLE_FEAT")
    if pkt is None:
        print("  TIMEOUT: BLE_FEAT"); return False

    # 3. Write WATCH_NAME — identity confirm (WRITE_REQ to ALL_FEAT)
    await w_all(client, bytes([FEAT_WATCH_NAME]) + b"CASIO GBD-200\x00\x00\x00\x00\x00\x00",
                "write WATCH_NAME (identity confirm)")

    # 4. Request MODULE_ID
    pkt = await req_wait(FEAT_MODULE_ID, "request MODULE_ID")
    if pkt is None:
        print("  TIMEOUT: MODULE_ID"); return False

    # 5. WATCH_COND + VER_INFO × 2 rounds, then one final WATCH_COND
    for i in range(2):
        pkt = await req_wait(FEAT_WATCH_COND, f"WATCH_COND {i+1}")
        if pkt is None:
            print(f"  TIMEOUT: WATCH_COND {i+1}"); return False
        pkt = await req_wait(FEAT_VERSION_INFO, f"VER_INFO {i+1}")
        if pkt is None:
            print(f"  TIMEOUT: VER_INFO {i+1}"); return False
    pkt = await req_wait(FEAT_WATCH_COND, "WATCH_COND 3")
    if pkt is None:
        print("  TIMEOUT: WATCH_COND 3"); return False

    # 6. DST_WATCH_STATE — read and echo back
    pkt = await req_wait(FEAT_DST_WATCH, "request DST_WATCH_STATE 0x1d")
    if pkt is None:
        print("  TIMEOUT: DST_WATCH_STATE"); return False
    await w_all(client, bytes(pkt), "echo DST_WATCH_STATE")

    # 7. DST_SETTING slots 0 and 1 — read both, then echo both
    await w_req(client, bytes([FEAT_DST_SETTING]), "request DST_SETTING slot 0")
    dst0 = await wait_for(all_feat_q, lambda d: d[0] == FEAT_DST_SETTING, timeout=5)
    if dst0 is None:
        print("  TIMEOUT: DST_SETTING slot 0"); return False
    await w_req(client, bytes([FEAT_DST_SETTING]), "request DST_SETTING slot 1")
    dst1 = await wait_for(all_feat_q, lambda d: d[0] == FEAT_DST_SETTING, timeout=5)
    if dst1 is None:
        print("  TIMEOUT: DST_SETTING slot 1"); return False
    await w_all(client, bytes(dst0), "echo DST_SETTING slot 0")
    await w_all(client, bytes(dst1), "echo DST_SETTING slot 1")

    # 8. Write GPS data — push two chunks (no read, just write)
    await w_all(client, GPS_CHUNK_0, "write GPS chunk 0 (0x24)")
    await w_all(client, GPS_CHUNK_1, "write GPS chunk 1 (0x24)")

    # 9. WORLD_CITY slots 0 and 1 — read both, echo both
    await w_req(client, bytes([FEAT_WORLD_CITY, 0x00]), "request WORLD_CITY slot 0")
    city0 = await wait_for(all_feat_q, lambda d: d[0] == FEAT_WORLD_CITY, timeout=5)
    if city0 is None:
        print("  TIMEOUT: WORLD_CITY slot 0"); return False
    await w_req(client, bytes([FEAT_WORLD_CITY, 0x01]), "request WORLD_CITY slot 1")
    city1 = await wait_for(all_feat_q, lambda d: d[0] == FEAT_WORLD_CITY, timeout=5)
    if city1 is None:
        print("  TIMEOUT: WORLD_CITY slot 1"); return False
    await w_all(client, bytes(city0), "echo WORLD_CITY slot 0")
    await w_all(client, bytes(city1), "echo WORLD_CITY slot 1")

    # 10. FEAT_2F — read and echo back
    pkt = await req_wait(FEAT_FEAT_2F, "request FEAT_2F 0x2f")
    if pkt is None:
        print("  TIMEOUT: FEAT_2F"); return False
    await w_all(client, bytes(pkt), "echo FEAT_2F")

    # 11. USER_PROF — read and echo back
    pkt = await req_wait(FEAT_USER_PROF, "request USER_PROF 0x45")
    if pkt is None:
        print("  TIMEOUT: USER_PROF"); return False
    await w_all(client, bytes(pkt), "echo USER_PROF")

    # 12. Write current time
    await cmd_time(client)

    # 13. Wait for 47 01 (INITIALIZED)
    print("  Waiting for 47 01 …")
    pkt = await wait_for(all_feat_q, lambda d: d[0] == FEAT_SVC_DISC and len(d) > 1 and d[1] == 0x01, timeout=30)
    if pkt is None:
        print("  TIMEOUT waiting for 47 01"); return False
    print("  ✓ 47 01 → INITIALIZED")

    # 14. Post-init reads (matches btsnoop pkt 454-467)
    await w_req(client, bytes([FEAT_WATCH_COND]), "post-init WATCH_COND")
    await wait_for(all_feat_q, lambda d: d[0] == FEAT_WATCH_COND, timeout=3)
    await w_req(client, bytes([0x13]), "post-init BASIC 0x13")
    await wait_for(all_feat_q, lambda d: d[0] == 0x13, timeout=3)
    await w_req(client, bytes([FEAT_VERSION_INFO]), "post-init VER_INFO")
    await wait_for(all_feat_q, lambda d: d[0] == FEAT_VERSION_INFO, timeout=3)
    await w_req(client, bytes([FEAT_WATCH_COND]), "post-init WATCH_COND #2")
    await wait_for(all_feat_q, lambda d: d[0] == FEAT_WATCH_COND, timeout=3)

    return True

# ── Post-init config sync (SetConfigurationOperation equivalent) ──────────────
async def sync_config(client):
    """
    Request and write back user profile (0x45), target values (0x43), and
    basic settings (0x13).  This completes the connection sequence that
    SetConfigurationOperation performs in Gadgetbridge, preventing the watch
    from displaying 'connection failed'.
    We echo the data back unmodified — just satisfying the watch's expectation.
    """
    print("=== SYNC CONFIG (0x45 / 0x43 / 0x13) ===")
    await drain(all_feat_q)
    for feat in (0x45, 0x13):
        await w_req(client, bytes([feat]), f"request 0x{feat:02x}")
        pkt = await wait_for(all_feat_q, lambda d, f=feat: d[0] == f, timeout=5)
        if pkt is None:
            print(f"  TIMEOUT: no response for 0x{feat:02x} — skipping")
            continue
        await w_all(client, bytes(pkt), f"echo back 0x{feat:02x}")
        await asyncio.sleep(0.1)
    # TARGET_VAL needs the proper two-cycle exchange
    await _target_val_exchange(client)
    print("  Config sync done.")

# ── Main-menu re-sync (handles '3d 01' BLE_PARAM notification) ───────────────
async def handle_main_menu_resync(client):
    """
    When the watch sends '3d 01' on ALL_FEAT it signals that the user navigated
    to the main menu.  All three working probe logs (btsnoop_hci_1–3) show the
    required recovery sequence:

        1. Enable CCCDs (h0011, h0014)
        2. Fetch step count (00 11) — this warms up h0011 and resets the
           watch's CONVOY state machine; skipping it causes the h0011 echo to
           arrive late (after cap_query) and blocks the sport handshake
        3. ACK steps (04 11)
        4. Disable CCCDs
        5. Re-enable CCCDs — fresh slate for subsequent sport/steps
    """
    global _main_menu_event, _resync_lock
    async with _resync_lock:
        if not _main_menu_event:
            return
        _main_menu_event = False
    print("=== MAIN MENU RESYNC (3d 01) ===")

    # Let any companion packets (3d 11, 39 00) arrive, then discard everything
    await asyncio.sleep(0.3)
    await drain(all_feat_q)
    await drain(h0011_q)
    await drain(h0014_q)

    # Step 1: enable CCCDs
    try:
        await client.stop_notify(UUID_DATA_REQ)
        await client.stop_notify(UUID_CONVOY)
    except Exception:
        pass
    await asyncio.sleep(0.1)
    await client.start_notify(UUID_DATA_REQ, cb_h0011)
    await client.start_notify(UUID_CONVOY,   cb_h0014)
    await asyncio.sleep(0.2)

    # Step 2+3: fetch steps to warm up h0011 / reset CONVOY state machine
    print("  Fetching steps (required after 3d 01 to warm up h0011)…")
    await w11(client, bytes([0x00, 0x11, 0x00, 0x00, 0x00]), "resync steps request")
    h11 = await wait_for(h0011_q, lambda d: len(d) >= 2 and d[0] == 0x00 and d[1] == 0x11, timeout=6)
    if h11 is not None:
        # drain any CONVOY step data, then ACK
        await asyncio.sleep(0.5)
        await drain(h0014_q)
        await w11(client, bytes([0x04, 0x11, 0x00, 0x00, 0x00]), "resync steps ACK")
        await asyncio.sleep(0.2)
        await drain(h0011_q)
        print("  Steps fetched OK")
    else:
        print("  WARNING: no steps echo — continuing anyway")
    await drain(h0014_q)

    # Steps 4+5: disable then re-enable CCCDs (matches working log pattern)
    try:
        await client.stop_notify(UUID_DATA_REQ)
        await client.stop_notify(UUID_CONVOY)
    except Exception:
        pass
    await asyncio.sleep(0.1)
    await client.start_notify(UUID_DATA_REQ, cb_h0011)
    await client.start_notify(UUID_CONVOY,   cb_h0014)
    await asyncio.sleep(0.2)

    # In some watch states (logs 1&2) the watch sends '48 00' on ALL_FEAT
    # immediately after CCCDs are re-enabled.  Respond with '48 03' params if so.
    feat48 = await wait_for(all_feat_q, lambda d: len(d) >= 1 and d[0] == 0x48, timeout=1)
    if feat48 is not None:
        print(f"  Watch sent 48 {feat48[1]:02x} — responding with 48 03 params")
        await w_all(client, bytes.fromhex("4803 00c8 0014 0a00 0034 0140 0101 00dc 05".replace(" ","")),
                    "48 03 CONVOY params")

    print("  CCCDs re-enabled — ready for sport/steps.")


# ── Command: send current time ────────────────────────────────────────────────
async def cmd_time(client):
    now = datetime.datetime.now()
    # Casio day-of-week: Sunday=0, Monday=1, …, Saturday=6
    dow = (now.weekday() + 1) % 7
    pkt = bytes([FEAT_CURRENT_TIME,
                 now.year & 0xff, (now.year >> 8) & 0xff,
                 now.month, now.day,
                 now.hour, now.minute, now.second,
                 dow, 0x00, 0x01])  # fractions256=0, reason=1 (sync)
    print(f"  Sending time: {now.strftime('%Y-%m-%d %H:%M:%S')} dow={dow}")
    await w_all(client, pkt, "write current time")

# ── Command: step count ───────────────────────────────────────────────────────
async def cmd_steps(client):
    global convoy_collecting
    await handle_main_menu_resync(client)
    print("=== STEPS ===")
    convoy_collecting = False
    await drain(h0011_q)
    await drain(h0014_q)

    await w11(client, bytes([0x00, 0x11, 0x00, 0x00, 0x00]), "request steps")

    # Watch notifies h0011 with incoming data length
    pkt = await wait_for(h0011_q, lambda d: True, timeout=5)
    if pkt and len(pkt) > 3:
        length = (pkt[2] & 0xff) | ((pkt[3] & 0xff) << 8)
        print(f"  Incoming: {length} bytes")

    # Watch notifies h0014 (CONVOY) with step count data — ALL bytes XOR'd
    raw = await wait_for(h0014_q, lambda d: len(d) >= 18, timeout=10)
    if raw is None:
        print("  TIMEOUT: no step count data on CONVOY"); return

    data = xor_all(raw)
    payload_len = (data[0] & 0xff) | ((data[1] & 0xff) << 8)
    year   = data[2] + 2000
    month  = data[3]
    day    = data[4]
    hour   = data[5]
    minute = data[6]
    steps    = struct.unpack('<I', data[7:11])[0]
    if steps == 0xfffffffe: steps = 0
    calories = struct.unpack('<H', data[11:13])[0]
    if calories == 0xfffe: calories = 0
    year_birth  = struct.unpack('<H', data[13:15])[0]
    month_birth = data[15]
    day_birth   = data[16]
    has_history = (data[17] == 0x00 and len(data) > 18)

    print(f"  As of {year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}")
    print(f"  Steps: {steps}  Calories: {calories} kcal")
    print(f"  Birth: {year_birth}-{month_birth:02d}-{day_birth:02d}")

    if has_history:
        print("  Hourly history:")
        index = 18
        while index + 2 < len(data):
            dtype       = data[index]
            block_len   = (data[index+1] & 0xff) | ((data[index+2] & 0xff) << 8)
            index      += 3
            items        = block_len // 2
            label        = "steps" if dtype == DATATYPE_STEPS else \
                           "kcal"  if dtype == DATATYPE_CALORIES else f"type{dtype:#04x}"
            counts = []
            for _ in range(items):
                if index + 1 >= len(data): break
                count = struct.unpack('<H', data[index:index+2])[0]
                if count == 0xfffe: count = 0
                counts.append(count)
                index += 2
            if counts:
                hrs = [f"{hour-len(counts)+i+1:02d}h:{v}" for i, v in enumerate(counts)]
                print(f"    [{label}] " + "  ".join(hrs))

    await w11(client, bytes([0x04, 0x11, 0x00, 0x00, 0x00]), "ACK steps")
    print("  Done.")


# ── Command: sport activities (CONVOY) ────────────────────────────────────────
async def cmd_sport(client):
    global convoy_buf, convoy_collecting
    await handle_main_menu_resync(client)

    # CONVOY handshake
    print("=== SPORT: CONVOY HANDSHAKE ===")
    convoy_collecting = False
    await drain(h0014_q)
    await drain(h0011_q)

    try:
        await w11(client, feat_req(0x1c, 0, 0),       "0x1c INIT request")
        await w14(client, bytes([0x00, 0x00, 0x00]),   "CONVOY ping")

        # Wait for ping echo.  In rare cases (watch CONVOY state not yet reset)
        # the watch returns '00 01 04' (BUSY) instead of '00 00 00'.
        echo = await wait_for(h0014_q, lambda d: d[0] == 0x00, timeout=6)
        if echo is None:
            print("TIMEOUT: no CONVOY 0x00 ping echo"); return

        if len(echo) >= 2 and echo[1] == 0x01:
            # Watch is BUSY — cancel this attempt, let it settle, then retry once
            print(f"  Watch BUSY ({xd(echo[:4])}) — cancelling and waiting for WATCH_COND ready")
            await w14(client, bytes([0x03, 0x00]), "CONVOY cancel (busy)")
            await w11(client, bytes([0x03, 0x1c] + [0x00]*8), "cancel 0x1c session")
            try:
                await client.stop_notify(UUID_DATA_REQ)
                await client.stop_notify(UUID_CONVOY)
            except Exception:
                pass
            # Wait for WATCH_COND with last byte = 0x01 (CONVOY ready)
            ready = await wait_for(all_feat_q,
                lambda d: d[0] == 0x28 and len(d) >= 8 and d[7] == 0x01, timeout=30)
            if ready is None:
                print("TIMEOUT: watch never became CONVOY-ready"); return
            print(f"  WATCH_COND ready: {xd(ready)}")
            await client.start_notify(UUID_DATA_REQ, cb_h0011)
            await client.start_notify(UUID_CONVOY,   cb_h0014)
            await asyncio.sleep(0.2)
            await drain(h0014_q)
            await drain(h0011_q)
            # Retry init + ping
            await w11(client, feat_req(0x1c, 0, 0), "0x1c INIT request (retry)")
            await w14(client, bytes([0x00, 0x00, 0x00]), "CONVOY ping (retry)")
            echo = await wait_for(h0014_q, lambda d: d[0] == 0x00, timeout=6)
            if echo is None:
                print("TIMEOUT: no CONVOY ping echo after retry"); return

        # Wait for h0011 echo before sending cap_query.  Official Casio app logs
        # show this echo arrives ~7.9s after the ping echo — the watch is loading
        # sport data from flash.  Must wait the full duration before cap_query.
        init_echo = await wait_for(h0011_q, lambda d: len(d) >= 2 and d[0] == 0x00 and d[1] == 0x1c, timeout=12)
        if init_echo is None:
            print("  WARNING: no h0011 0x1c echo — proceeding anyway")

        await w14(client, bytes([0x04] + [0x00] * 9), "CONVOY cap_query")

        pkt = await wait_for(h0014_q, lambda d: d[0] == 0x04, timeout=10)
        if pkt is None:
            print("TIMEOUT: no CONVOY 0x04 cap response"); return
        await w14(client, bytes([0x04,0x01,0x18,0x00,0x18,0x00,0x00,0x00,0xdc,0x05]), "cap_set")

        pkt = await wait_for(h0014_q, lambda d: d[0] == 0x04, timeout=6)
        if pkt is None:
            print("TIMEOUT: no CONVOY 0x04 cap confirm"); return
        await w14(client, bytes([0x06] + [0x00] * 13), "init_sig")

        ver = await wait_for(h0014_q, lambda d: d[0] == 0x06, timeout=6)
        if ver is None:
            print("TIMEOUT: no CONVOY 0x06 version"); return
        await w14(client, bytes(ver), "version echo")
        await asyncio.sleep(0.3)

        # Session list
        print("\n=== SPORT: SESSION LIST (0x1d) ===")
        convoy_buf = bytearray(); convoy_collecting = True
        await drain(h0011_q)

        await w11(client, feat_req(0x1d, SESSION_LIST_BASE, 0x01), "list request")
        sig = await wait_for(h0011_q, lambda d: d[0] == 0x09, timeout=10)
        if sig is None:
            print("TIMEOUT: no 0x09 DATA_READY for session list"); return
        print(f"  0x09 received, payload={len(convoy_buf)} bytes")

        payload = bytes(convoy_buf)
        for i in range(0, len(payload), 16):
            print(f"    [{i:3d}] {xd(payload[i:i+16])}")

        if len(payload) > 9:
            total_sessions = sum(bin((~payload[i]) & 0xff).count('1')
                                 for i in range(6, min(10, len(payload))))
            newest_offset  = SESSION_LIST_BASE + 0x40 + total_sessions
            print(f"  Sessions: {total_sessions}  newest=0x{newest_offset:04x}")
        else:
            total_sessions = 0

        await w11(client, echo10(sig), "echo 0x09")
        await w11(client, ack(0x1d),   "ACK 0x1d")
        await asyncio.sleep(0.2)

        # Per-session summaries
        for n in range(1, total_sessions + 1):
            addr = SESSION_LIST_BASE + 0x40 + n
            print(f"\n=== SPORT: SUMMARY {n}/{total_sessions} @ 0x{addr:04x} ===")
            convoy_buf = bytearray(); convoy_collecting = True
            await drain(h0011_q)

            await w11(client, feat_req(0x1e, addr, 0x01), f"summary @ 0x{addr:04x}")
            sig = await wait_for(h0011_q, lambda d: d[0] == 0x09, timeout=10)
            if sig is None:
                print(f"  TIMEOUT: no 0x09 for summary {n}"); break

            payload = bytes(convoy_buf)
            print(f"  Payload: {len(payload)} bytes")
            print(f"  First 48B: {xd(payload[:48])}")
            ma = seg_count = 0
            if len(payload) >= 186:
                def bd(i): return payload[i-3] if i >= 3 else 0
                def bcd(b): return ((b >> 4) & 0xf) * 10 + (b & 0xf)
                def bcd_ts(base):
                    year = bcd(bd(base+1)) * 100 + bcd(bd(base))
                    mon  = bcd(bd(base+2)); day = bcd(bd(base+3))
                    h    = bcd(bd(base+4)); m   = bcd(bd(base+5)); s = bcd(bd(base+6))
                    return f"{year:04d}-{mon:02d}-{day:02d} {h:02d}:{m:02d}:{s:02d}"
                dur       = bd(177)*60 + bd(178)
                avg_min   = bd(179); avg_sec = bd(180)
                kcal      = bd(181); cad = bd(185)
                ta        = bd(165) | (bd(166) << 8)
                ma        = bd(169) | (bd(170) << 8)
                seg_count = bd(145)
                dist_km   = struct.unpack('<f', bytes([bd(172), bd(173), bd(174), bd(175)]))[0]
                start_ts  = bcd_ts(150)
                end_ts    = bcd_ts(157)
                print(f"  start={start_ts}  end={end_ts}")
                print(f"  dur={dur}s ({dur//60}m{dur%60}s)  avg={avg_min}'{avg_sec}''  kcal={kcal}  cad={cad}")
                print(f"  dist={dist_km:.3f}km  segs={seg_count}  trackAddr=0x{ta:04x}  metaAddr=0x{ma:04x}")

            await w11(client, echo10(sig), "echo 0x09")
            await w11(client, ack(0x1e),   "ACK 0x1e")
            await asyncio.sleep(0.2)

            # Fetch meta block (feature 0x20) — contains per-lap data (19 bytes per lap)
            if len(payload) >= 186 and ma != 0 and ma != 0xffff:
                convoy_buf = bytearray(); convoy_collecting = True
                await drain(h0011_q)
                await w11(client, feat_req(0x20, ma, 0x01), f"meta @ 0x{ma:04x}")
                sig2 = await wait_for(h0011_q, lambda d: d[0] in (0x07, 0x09), timeout=10)
                if sig2 is None:
                    print(f"  TIMEOUT: no 0x09 for meta block")
                else:
                    meta_payload = bytes(convoy_buf)
                    block = meta_payload  # cb_h0014 already XOR-decoded and stripped dec[0:3]
                    print(f"  Meta block: {len(block)} bytes (after header strip)")
                    if seg_count > 0:
                        print(f"  Laps ({seg_count}):")
                        for s in range(seg_count):
                            base = META_BLOCK_HDR + s * META_LAP_STRIDE
                            if base + META_LAP_STRIDE > len(block):
                                break
                            lap = block[base:base + META_LAP_STRIDE]
                            dist_l  = struct.unpack_from('<f', lap, 0)[0]
                            el_s    = lap[5] * 60 + lap[6]
                            dur_s   = lap[8] * 60 + lap[9]
                            pace_s  = lap[10] * 60 + lap[11]
                            cal_l   = lap[12]
                            cad_l   = lap[16]
                            pace_str = f"{pace_s//60}'{pace_s%60:02d}''" if pace_s else "--'--''"
                            print(f"    lap {s+1}: {dist_l:.3f}km  {dur_s//60}m{dur_s%60:02d}s"
                                  f"  pace={pace_str}  {cal_l}kcal  {cad_l}spm"
                                  f"  (cumul {el_s//60}m{el_s%60:02d}s)")
                    await w11(client, echo10(sig2), "echo 0x09 meta")
                    await w11(client, ack(0x20),    "ACK 0x20 meta")
                    await asyncio.sleep(0.2)

    finally:
        # Official app closes with 03 1c (cancel), not 04 1c (ACK).
        print("\n=== Closing sport session ===")
        try:
            await w11(client, bytes([0x03, 0x1c] + [0x00]*8), "close 0x1c session")
        except Exception as e:
            print(f"  (close error: {e})")
        await asyncio.sleep(0.3)
        convoy_collecting = False

# ── Command: goals (TARGET_VAL 0x43) ─────────────────────────────────────────

def _build_target_val_echo(pkt, kcal_day=None, dist_day_km=None):
    """
    Build the 15-byte echo frame the phone sends back for TARGET_VAL.

    The watch response carries:
      bytes[1:3]  LE16  daily step goal
      bytes[6:8]  LE16  monthly distance goal (unit = 100 m)
      bytes[9:11] LE16  monthly time goal (unit = minutes)

    The phone adds (only when the values are provided):
      bytes[4:6]  LE16  daily kcal goal
      bytes[11:13] LE16  daily distance goal (unit = 5 m)
    """
    frame = bytearray(pkt[:15])
    frame[0] = FEAT_TARGET_VAL
    # sub-type is always 0x34 in phone echoes regardless of what watch sent
    steps = struct.unpack_from('<H', frame, 1)[0]
    frame[1] = steps & 0xff
    frame[2] = (steps >> 8) & 0xff
    if kcal_day is not None:
        struct.pack_into('<H', frame, 4, kcal_day)
    if dist_day_km is not None:
        struct.pack_into('<H', frame, 11, round(dist_day_km * 1000 / 5))
    return bytes(frame)


async def _target_val_exchange(client, steps_day=None, kcal_day=None,
                               dist_day_km=None, dist_month_km=None,
                               time_month_h=None):
    """
    Perform the two-cycle TARGET_VAL (0x43) exchange.

    If any goal argument is non-None the corresponding field is overwritten in
    the echo frame sent back to the watch, effectively setting that goal.
    Returns (steps_day, dist_month_km, time_month_h) read from the watch.
    """
    await drain(all_feat_q)

    # ── Cycle 1: watch sends sub-type 0x40 ──────────────────────────────────
    await w_req(client, bytes([FEAT_TARGET_VAL]), "request TARGET_VAL (1/2)")
    pkt = await wait_for(all_feat_q, lambda d: d[0] == FEAT_TARGET_VAL, timeout=5)
    if pkt is None:
        print("  TIMEOUT: no TARGET_VAL response"); return None

    rd_steps     = struct.unpack_from('<H', pkt, 1)[0]
    rd_dist_mo   = struct.unpack_from('<H', pkt, 6)[0]   # × 100 m → km
    rd_time_mo   = struct.unpack_from('<H', pkt, 9)[0]   # minutes

    # Build echo: overwrite goals if caller supplied them
    echo1 = bytearray(_build_target_val_echo(pkt, kcal_day=kcal_day))
    if steps_day     is not None: struct.pack_into('<H', echo1, 1,  steps_day)
    if dist_month_km is not None: struct.pack_into('<H', echo1, 6,  round(dist_month_km * 10))
    if time_month_h  is not None: struct.pack_into('<H', echo1, 9,  round(time_month_h * 60))
    await w_all(client, bytes(echo1), "echo TARGET_VAL (1/2)")

    # ── Cycle 2: watch sends sub-type 0x34 ──────────────────────────────────
    await w_req(client, bytes([FEAT_TARGET_VAL]), "request TARGET_VAL (2/2)")
    pkt2 = await wait_for(all_feat_q, lambda d: d[0] == FEAT_TARGET_VAL, timeout=5)
    if pkt2 is None:
        print("  TIMEOUT: no 2nd TARGET_VAL response"); return None

    echo2 = bytearray(_build_target_val_echo(pkt2, dist_day_km=dist_day_km))
    if steps_day     is not None: struct.pack_into('<H', echo2, 1,  steps_day)
    if dist_month_km is not None: struct.pack_into('<H', echo2, 6,  round(dist_month_km * 10))
    if time_month_h  is not None: struct.pack_into('<H', echo2, 9,  round(time_month_h * 60))
    await w_all(client, bytes(echo2), "echo TARGET_VAL (2/2)")

    return rd_steps, rd_dist_mo / 10.0, rd_time_mo / 60.0


async def cmd_goals(client):
    """Read and display all goals from TARGET_VAL (0x43)."""
    print("=== GOALS (0x43 TARGET_VAL) ===")
    result = await _target_val_exchange(client)
    if result is None:
        return
    steps, dist_mo, time_mo = result
    print(f"  Daily steps:      {steps} steps/day")
    print(f"  Monthly distance: {dist_mo:.1f} km/month")
    print(f"  Monthly time:     {time_mo:.2f} h/month  ({round(time_mo*60)} min)")
    print("  (daily kcal and daily distance are phone-side only — not readable from watch)")


async def cmd_setgoals(client, steps_day, kcal_day, dist_day_km,
                       dist_month_km, time_month_h):
    """Write updated goals via TARGET_VAL (0x43)."""
    print("=== SET GOALS (0x43 TARGET_VAL) ===")
    print(f"  steps/day={steps_day}  kcal/day={kcal_day}  dist/day={dist_day_km} km")
    print(f"  dist/month={dist_month_km} km  time/month={time_month_h} h")
    result = await _target_val_exchange(
        client,
        steps_day=steps_day,
        kcal_day=kcal_day,
        dist_day_km=dist_day_km,
        dist_month_km=dist_month_km,
        time_month_h=time_month_h,
    )
    if result is None:
        return
    print("  Goals written.")


# ── Command: send notification ────────────────────────────────────────────────
_notif_counter = 1

async def cmd_notify(client, sender="", title="", subtitle="", message="", alert=True):
    global _notif_counter
    notif_id = _notif_counter; _notif_counter += 1

    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    hdr = bytearray(22)
    hdr[0] = notif_id & 0xff
    hdr[1] = (notif_id >> 8) & 0xff
    hdr[2] = (notif_id >> 16) & 0xff
    hdr[3] = (notif_id >> 24) & 0xff
    hdr[4] = 0x00              # add notification (0x02 = delete)
    hdr[5] = 0x01 if alert else 0x00
    hdr[6] = 0x0d             # SNS icon (13)
    hdr[7:22] = ts.encode()[:15]

    def tlv(s):
        """Build LE16-length-prefixed field (zero-length = 2 zero bytes)."""
        b = s.encode('utf-8') if s else b''
        return struct.pack('<H', len(b)) + b

    pkt = bytes(hdr) + tlv(sender) + tlv(title) + tlv(subtitle) + tlv(message)
    encoded = bytes(~b & 0xff for b in pkt)

    print(f"  Notification #{notif_id}: sender={sender!r} title={title!r} message={message!r}")
    print(f"  Encoded ({len(encoded)}B): {xd(encoded[:32])}{'…' if len(encoded)>32 else ''}")
    await client.write_gatt_char(UUID_NOTIF, encoded, response=False)
    print("  Sent.")

# ── Interactive REPL ──────────────────────────────────────────────────────────
HELP = """
Commands:
  steps                          Fetch step count and hourly history
  sport                          Fetch all sport activity sessions
  goals                          Show current goals (TARGET_VAL 0x43)
  setgoals <steps> <kcal> <km/d> <km/mo> <h/mo>
                                 Set goals  e.g. setgoals 8500 2300 5 30 6
  notify [msg]                   Send a notification (SNS icon, vibrate)
  notify sender|title|msg        Send with explicit sender, title, message
  time                           Resend current time to watch
  config                         Re-send config sync (0x45/0x43/0x13) to clear "connection failed"
  raw <hex ...>                  Write raw hex bytes to DATA_REQUEST_SP
  help                           Show this help
  quit / exit                    Disconnect and exit
"""

async def interactive_loop(client):
    loop = asyncio.get_event_loop()
    print(HELP)
    print("Ready. Type a command:")
    while True:
        if _disconnect_event.is_set():
            return "disconnected"

        try:
            line = await loop.run_in_executor(None, lambda: input("\n> "))
        except (EOFError, KeyboardInterrupt):
            print("\nInterrupted.")
            return "quit"

        if _disconnect_event.is_set():
            return "disconnected"

        parts = line.strip().split()
        if not parts:
            continue
        cmd = parts[0].lower()

        if cmd in ('quit', 'exit', 'q'):
            return "quit"

        try:
            if cmd == 'help':
                print(HELP)
            elif cmd == 'time':
                await cmd_time(client)
            elif cmd == 'config':
                await sync_config(client)
            elif cmd == 'steps':
                await cmd_steps(client)
            elif cmd == 'sport':
                await cmd_sport(client)
            elif cmd == 'goals':
                await cmd_goals(client)
            elif cmd == 'setgoals':
                if len(parts) != 6:
                    print("  Usage: setgoals <steps/day> <kcal/day> <km/day> <km/month> <h/month>")
                    print("  Example: setgoals 8500 2300 5 30 6")
                else:
                    await cmd_setgoals(client,
                        steps_day=int(parts[1]),
                        kcal_day=int(parts[2]),
                        dist_day_km=float(parts[3]),
                        dist_month_km=float(parts[4]),
                        time_month_h=float(parts[5]))
            elif cmd == 'notify':
                rest = line.strip()[len('notify'):].strip()
                fields = rest.split('|')
                if len(fields) == 3:
                    await cmd_notify(client, sender=fields[0], title=fields[1], message=fields[2])
                elif len(fields) == 2:
                    await cmd_notify(client, title=fields[0], message=fields[1])
                else:
                    await cmd_notify(client, title="Probe", message=rest or "test notification")
            elif cmd == 'raw':
                raw = bytes(int(x, 16) for x in parts[1:])
                if not raw:
                    print("  Usage: raw <hex bytes>  e.g. raw 00 11 00 00 00")
                else:
                    await w11(client, raw, "raw command")
            else:
                print(f"  Unknown command: {cmd!r}  (type 'help')")
        except Exception as e:
            print(f"\n  !! Command '{cmd}' failed: {type(e).__name__}: {e}")
            if not client.is_connected or _disconnect_event.is_set():
                return "disconnected"

    return "quit"

# ── Main ──────────────────────────────────────────────────────────────────────
RECONNECT_DELAY = 5  # seconds between reconnect attempts

async def main():
    global _resync_lock, _g_client
    _resync_lock = asyncio.Lock()

    first = True
    while True:
        _disconnect_event.clear()
        _reset_queues()

        print(f"{'Connecting' if first else 'Reconnecting'} to {ADDR} …")
        first = False
        try:
            async with BleakClient(ADDR, timeout=20,
                                   disconnected_callback=_on_disconnect) as client:
                _g_client = client
                print(f"Connected! MTU={client.mtu_size}")

                if not await init_handshake(client):
                    print(f"Init handshake failed — retrying in {RECONNECT_DELAY}s")
                    await asyncio.sleep(RECONNECT_DELAY)
                    continue

                await client.start_notify(UUID_DATA_REQ, cb_h0011)
                await client.start_notify(UUID_CONVOY,   cb_h0014)
                await asyncio.sleep(0.3)

                reason = await interactive_loop(client)
                if reason == "quit":
                    print("Disconnecting …")
                    break

        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\nAborted.")
            break
        except Exception as e:
            print(f"  Connection error: {type(e).__name__}: {e}")

        print(f"Reconnecting in {RECONNECT_DELAY}s …")
        await asyncio.sleep(RECONNECT_DELAY)

asyncio.run(main())
