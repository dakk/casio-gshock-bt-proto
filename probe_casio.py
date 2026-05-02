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

# ── Characteristic UUIDs ──────────────────────────────────────────────────────
UUID_ALL_FEAT = "26eb002d-b012-49a8-b1f8-394fb2032b0f"  # ALL_FEATURES (write + notify)
UUID_ALL_REQ  = "26eb002c-b012-49a8-b1f8-394fb2032b0f"  # READ_REQUEST_FOR_ALL_FEATURES
UUID_DATA_REQ = "26eb0023-b012-49a8-b1f8-394fb2032b0f"  # DATA_REQUEST_SP (h0011)
UUID_CONVOY   = "26eb0024-b012-49a8-b1f8-394fb2032b0f"  # CONVOY (h0014)
UUID_NOTIF    = "26eb0030-b012-49a8-b1f8-394fb2032b0f"  # NOTIFICATION

SESSION_LIST_BASE = 0x46a0

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
FEAT_CONN_PARAM   = 0x3a
FEAT_ADVERT_PARAM = 0x3b
FEAT_SVC_DISC     = 0x47
FEAT_CURRENT_TIME = 0x09

# Default GPS data from btsnoop reference log (Rome area).
# Chunk format: 0x24, index, flag, lat_double_BE(8B), lon_double_BE(8B), ...
GPS_CHUNK_0 = bytes.fromhex("24000140439beef515c132402288c48783ed6004")
GPS_CHUNK_1 = bytes.fromhex("2401014049c00000000000000000000000000000")

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

def cb_all_feat(_, data):
    data = bytes(data)
    print(f"\r  [allFeat←] feat=0x{data[0]:02x} {len(data)}B  {xd(data[:16])}{'…' if len(data)>16 else ''}")
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
    for feat in (0x45, 0x43, 0x13):
        await w_req(client, bytes([feat]), f"request 0x{feat:02x}")
        pkt = await wait_for(all_feat_q, lambda d, f=feat: d[0] == f, timeout=5)
        if pkt is None:
            print(f"  TIMEOUT: no response for 0x{feat:02x} — skipping")
            continue
        await w_all(client, bytes(pkt), f"echo back 0x{feat:02x}")
        await asyncio.sleep(0.1)
    print("  Config sync done.")

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

    # Best-effort close any lingering 0x1c session from a previous crashed run.
    # The watch persists "session open" state and returns 0x81 if not properly closed.
    # Use response=True so the watch actually registers the close; catch any error
    # (ATT error 0x81 is raised when no session was open — safe to ignore).
    try:
        await w11(client, ack(0x1c), "pre-emptive close 0x1c (in case session lingered)")
    except Exception:
        pass
    await asyncio.sleep(0.3)

    # CONVOY handshake
    print("=== SPORT: CONVOY HANDSHAKE ===")
    convoy_collecting = False
    await drain(h0014_q)
    await drain(h0011_q)

    try:
        await w11(client, feat_req(0x1c, 0, 0),       "0x1c INIT request")
        await w14(client, bytes([0x00, 0x00, 0x00]),   "CONVOY ping")

        # Wait for watch to echo the ping (0x00) before proceeding
        echo = await wait_for(h0014_q, lambda d: d[0] == 0x00, timeout=6)
        if echo is None:
            print("TIMEOUT: no CONVOY 0x00 ping echo"); return

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
            raw_byte = payload[6]; inv_byte = (~raw_byte) & 0xff
            total_sessions = bin(inv_byte).count('1')
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
            if len(payload) >= 186:
                def bd(i): return payload[i-3] if i >= 3 else 0
                dur     = bd(177)*60 + bd(178)
                avg_min = bd(179); avg_sec = bd(180)
                kcal    = bd(181); cad = bd(185)
                ta = bd(165) | (bd(166) << 8)
                ma = bd(169) | (bd(170) << 8)
                dist_km = struct.unpack('<f', bytes([bd(172), bd(173), bd(174), bd(175)]))[0]
                print(f"  dur={dur}s ({dur//60}m{dur%60}s)  avg={avg_min}'{avg_sec}''  kcal={kcal}  cad={cad}")
                print(f"  dist={dist_km:.3f}km  trackAddr=0x{ta:04x}  metaAddr=0x{ma:04x}")

            await w11(client, echo10(sig), "echo 0x09")
            await w11(client, ack(0x1e),   "ACK 0x1e")
            await asyncio.sleep(0.2)

    finally:
        # Close the sport session with response=True so the watch actually registers it.
        # Without acknowledgment the watch keeps the session open and returns 0x81 on the next call.
        print("\n=== Closing sport session ===")
        try:
            await w11(client, ack(0x1c), "close 0x1c session")
        except Exception as e:
            print(f"  (close error: {e})")
        await asyncio.sleep(0.3)
        convoy_collecting = False

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
  steps                     Fetch step count and hourly history
  sport                     Fetch all sport activity sessions
  notify [msg]              Send a notification (SNS icon, vibrate)
  notify sender|title|msg   Send with explicit sender, title, message
  time                      Resend current time to watch
  config                    Re-send config sync (0x45/0x43/0x13) to clear "connection failed"
  raw <hex ...>             Write raw hex bytes to DATA_REQUEST_SP
  help                      Show this help
  quit / exit               Disconnect and exit
"""

async def interactive_loop(client):
    loop = asyncio.get_event_loop()
    print(HELP)
    print("Ready. Type a command:")
    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input("\n> "))
        except (EOFError, KeyboardInterrupt):
            print("\nInterrupted.")
            break

        parts = line.strip().split()
        if not parts:
            continue
        cmd = parts[0].lower()

        if cmd in ('quit', 'exit', 'q'):
            break

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
            if not client.is_connected:
                print("  Watch disconnected — exiting.")
                break

    print("Exiting REPL.")

# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    global convoy_buf, convoy_collecting

    print(f"Connecting to {ADDR} …")
    async with BleakClient(ADDR, timeout=20) as client:
        print(f"Connected! MTU={client.mtu_size}")

        if not await init_handshake(client):
            print("Init handshake failed — aborting")
            return

        # Enable DATA_REQUEST_SP and CONVOY notifications (stay active for all commands)
        await client.start_notify(UUID_DATA_REQ, cb_h0011)
        await client.start_notify(UUID_CONVOY,   cb_h0014)
        await asyncio.sleep(0.3)

        await interactive_loop(client)

        print("Disconnecting …")

asyncio.run(main())
