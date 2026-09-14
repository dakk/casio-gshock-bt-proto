#!/usr/bin/env python3
"""
Interactive probe for the Casio GG-B100 (Mudmaster) BLE protocol.

Usage:  python3 probe_casio_ggb100.py MAC

The GG-B100 only advertises when it has a reason to talk (CONNECT button,
mission-log START/GOAL, Location Indicator mode, scheduled time adjustment),
so start the probe first and then press CONNECT on the watch.  The reason
byte the watch reports in BLE_FEATURES decides what the init does, the same
way the official app chooses its flow (PROTOCOL-GGB100.md, "Connection reasons"):

  0x04  manual sync          time-only flow
  0x07  Location Indicator   0x35 exchange; the watch's polls are then answered
                             with the distance/bearing set with `locind`
  other                      reads (BLE_SETTINGS, status block, NEW_DATA, version,
                             city block, mode customisation) and the time write

The data blocks are NOT fetched during the init: a fetch ends with an ACK and
the watch then clears the LIFE LOG hourly bins / day history and the mission-log
altitude series, so the official app would never see them.  Use `lifelog` and
`mission` explicitly (add `noack` to read without consuming).

Shared plumbing lives in casio_ble.py; everything here is GG-B100 specific.
"""
import asyncio, sys, struct
from bleak import BleakClient

from casio_ble import (CasioLink, xd, bcd_datetime, gps_chunk, city_name, data_req,
                       NO_DATA16, NO_DATA32,
                       FEAT_BLE_SETTINGS, FEAT_BASIC, FEAT_DST_WATCH, FEAT_DST_SETTING,
                       FEAT_WORLD_CITY, FEAT_VERSION_INFO, FEAT_APP_INFO, FEAT_WATCH_COND,
                       FEAT_FEAT_2F)

WATCH_NAME = "CASIO GG-B100"

# ── GG-B100-only feature ids ──────────────────────────────────────────────────
FEAT_STATUS    = 0x05   # DATA_REQUEST_SP: 00 05 1c 00 00 → 28-byte status block (undecoded)
FEAT_LIFELOG   = 0x11   # DATA_REQUEST_SP context (ALL_REQ 0x11 is BLE_SETTINGS)
FEAT_ALARM1    = 0x15
FEAT_ALARMS    = 0x16   # alarms 2-5, 4 bytes each
FEAT_CDT       = 0x18   # countdown timer
FEAT_MISSION   = 0x19   # DATA_REQUEST_SP context: mission-log block
FEAT_TRANSACT  = 0x21   # 21 00 <n> begin / 21 01 <n> end around city/DST edits
FEAT_LOC_IND   = 0x35
FEAT_NEW_DATA  = 0x37
FEAT_MODE_CUST = 0x38

REASONS = {0x01: "connect from the app", 0x03: "scheduled time adjustment",
           0x04: "manual sync (CONNECT)", 0x07: "Location Indicator",
           0x08: "mission log START/GOAL or hourly mid-mission offload"}
DST_MODES = {0x00: "off", 0x01: "on", 0x03: "auto"}
MODE_NAMES = {1: "BAROMETER", 2: "TEMPERATURE", 3: "RECALL", 4: "SUNRISE",
              5: "STOPWATCH", 6: "TIMER", 7: "ALARM", 8: "WORLD TIME"}
# Timekeeping display screens ("Mostra" tab), ids mapped by app row position (capture 3)
SCREEN_NAMES = {1: "Giorno e data", 2: "YEAR DATE", 3: "Grafico Pressione Barometrica ...",
                4: "Grafico Pressione Barometrica", 5: "ore / min / sec",
                6: "Ora Mondiale HH MM", 7: "STEPS (TODAY)", 8: "SUNRISE/SUNSET (TODAY)"}

# GPS chunk 0 = the phone's position (the home city is GPS-paired), chunk 1 =
# the world-time city's coordinates and must match the city stored on the watch.
GPS_LAT, GPS_LON     = 39.2182, 9.2670      # phone position
WORLD_LAT, WORLD_LON = 51.5074, -0.1278     # London, the world city of the captured watch

# Token the official app had stored on the captured watch; per pairing, read only.
APP_INFO_SEEN = bytes.fromhex("2255f65569262c6bb97b02")

# ── Location Indicator state (answered from the ALL_FEAT hook) ───────────────
_locind = {"session": False, "dist": None, "bearing": None}
_link = None   # current CasioLink, so the hook can schedule writes


def locind_reply(mode):
    """35 <mode> <st> <dist LE32 m> <bearing LE16 °>; st 01 = nothing to give."""
    if _locind["dist"] is None:
        return bytes([FEAT_LOC_IND, mode, 0x01]) + bytes(6)
    if mode != 0x02:
        return bytes([FEAT_LOC_IND, mode, 0x00]) + bytes(6)
    return (bytes([FEAT_LOC_IND, 0x02, 0x00]) + struct.pack('<I', _locind["dist"])
            + struct.pack('<H', _locind["bearing"]))


async def read_h0009(link):
    """The app reads the unidentified 1-byte characteristic at h0009 (always
    0xfa) before every Location Indicator write; mirror it, report what we get."""
    try:
        v = await link.client.read_gatt_char(0x0009)
        print(f"  [h0009←] {xd(v)}")
    except Exception as e:
        print(f"  (h0009 read failed: {type(e).__name__}: {e})")


async def _answer_locind_poll(link, mode):
    await read_h0009(link)
    await link.w_all(locind_reply(mode), "Location Indicator update")


def ggb100_events(data):
    """ALL_FEAT hook: answer Location Indicator polls while a session is open."""
    if data[0] == FEAT_LOC_IND and len(data) >= 2 and _locind["session"] and _link is not None:
        asyncio.get_running_loop().create_task(_answer_locind_poll(_link, data[1]))


async def locind_session_start(link):
    pkt = await link.request(FEAT_LOC_IND, label="request LOC_IND 0x35")
    if pkt is None:
        print("  TIMEOUT: 0x35"); return False
    mode = pkt[1]
    print(f"  Watch mode: {'Location Indicator' if mode == 0x02 else f'not in indicator mode ({mode:#04x})'}")
    await read_h0009(link)
    await link.w_all(locind_reply(mode), "Location Indicator accept")
    _locind["session"] = True
    if mode == 0x02 and _locind["dist"] is None:
        print("  No target set — answering polls with 'nothing'; use: locind <metres> <degrees>")
    return True


# ── Init ──────────────────────────────────────────────────────────────────────
async def version_round(link):
    """20 / 28 / 20 / 28, the order the GG-B100 app uses."""
    for feat, label in ((FEAT_VERSION_INFO, "VER_INFO 1"), (FEAT_WATCH_COND, "WATCH_COND 1"),
                        (FEAT_VERSION_INFO, "VER_INFO 2"), (FEAT_WATCH_COND, "WATCH_COND 2")):
        if await link.request(feat, label=label) is None:
            print(f"  TIMEOUT: {label}"); return False
    return True


def gps_chunks():
    return gps_chunk(0, GPS_LAT, GPS_LON), gps_chunk(1, WORLD_LAT, WORLD_LON)


async def init_handshake(link):
    print("=== INIT ===")
    await link.start()
    res = await link.init_prefix(WATCH_NAME)
    if res is None:
        return False
    app_info, ble_feat = res
    if bytes(app_info[1:]) != APP_INFO_SEEN:
        print("  (APP_INFO token differs from the captured one — expected on another pairing)")
    reason = ble_feat[8] if len(ble_feat) > 8 else -1
    print(f"  Connection reason 0x{reason:02x}: {REASONS.get(reason, 'unknown')}")

    if reason == 0x07:
        return await locind_session_start(link)

    if reason != 0x04:
        if await link.request_echo(FEAT_BLE_SETTINGS, label="request BLE_SETTINGS 0x11") is None:
            return False
        await cmd_status(link)
        await cmd_newdata(link)
    if not await version_round(link):
        return False
    if not await link.city_block(gps_chunks()):
        return False
    if reason != 0x04:
        await link.request(FEAT_MODE_CUST, label="request MODE_CUST 0x38")
    await link.write_time()
    return True


# ── Reads / fetches ───────────────────────────────────────────────────────────
async def cmd_newdata(link):
    pkt = await link.request(FEAT_NEW_DATA, label="request NEW_DATA 0x37")
    if pkt is None:
        print("  TIMEOUT: 0x37"); return None
    flags = pkt[1]
    parts = []
    if flags & 0x01:
        parts.append("mission-log record(s)")
    if flags & 0x02:
        parts.append("mission-log series/point data")
    if len(pkt) >= 8 and pkt[2] != 0xff:
        parts.append(f"location point saved {bcd_datetime(pkt[2:8])} UTC (the GOAL press)")
    print(f"  NEW_DATA: {', '.join(parts) if parts else 'nothing pending'}")
    return pkt


async def cmd_status(link):
    raw = await link.fetch(FEAT_STATUS, params=b'\x1c\x00\x00', toggle_cccd=True, timeout=5)
    if raw is None:
        return None
    print(f"  Status block ({len(raw)}B): {xd(raw)}")
    if len(raw) >= 5:
        print(f"    timestamp {bcd_datetime(raw[0:5])} (local; last scheduled time adjustment?), rest {xd(raw[5:])}")
    return raw


async def cmd_lifelog(link, ack=True):
    print("=== LIFE LOG (0x11) ===")
    raw = await link.fetch(FEAT_LIFELOG, toggle_cccd=True, ack=ack)
    if raw is None:
        return
    if len(raw) < 160:
        print(f"  Short payload ({len(raw)}B): {xd(raw)}"); return
    steps_h = struct.unpack('<24H', raw[0:48])
    kcal_h = struct.unpack('<24H', raw[48:96])
    steps, kcal = struct.unpack('<II', raw[96:104])
    hist = struct.unpack('<14I', raw[104:160])
    print(f"  Today: {steps} steps, {kcal} kcal (watch estimate)")
    hours = [(s, k) for s, k in zip(steps_h, kcal_h) if s != NO_DATA16 or k != NO_DATA16]
    if hours:
        print("  Completed hours since the last ACKed fetch (most recent first?):")
        for i, (s, k) in enumerate(hours):
            print(f"    [{i:2d}] {s:5d} steps  {k:4d} kcal")
    else:
        print("  No completed hour since the last fetch")
    days = [(hist[i], hist[i + 1]) for i in range(0, 14, 2) if hist[i] != NO_DATA32]
    if days:
        print("  Previous days not yet fetched (most recent first?):")
        for i, (s, k) in enumerate(days):
            print(f"    [{i}] {s} steps  {k} kcal")
    if not ack:
        print("  (not ACKed — the watch keeps the data)")


async def cmd_mission(link, ack=True):
    print("=== MISSION LOG (0x19) ===")
    raw = await link.fetch(FEAT_MISSION, toggle_cccd=True, ack=ack)
    if raw is None:
        return
    if len(raw) < 294:
        print(f"  Short payload ({len(raw)}B): {xd(raw)}"); return
    hdr = raw[0:6]
    if hdr[0] != 0xff:
        samples = struct.unpack('<60h', raw[6:126])
        vals = [v for v in samples if v != 0x7fff]
        print(f"  Altitude series from {bcd_datetime(hdr[0:5])} UTC, {hdr[5]} samples: {vals} m")
    else:
        print("  No altitude series stored")
    print("  Event records (oldest first; pairs = START / GOAL):")
    for i in range(14):
        r = raw[126 + 12 * i:138 + 12 * i]
        if r[2] == 0xff:
            continue
        alt = struct.unpack('<h', r[0:2])[0]
        print(f"    {bcd_datetime(r[2:8])} UTC  {alt:6d} m  [{xd(r[8:12])}]")
    if not ack:
        print("  (not ACKed — the watch keeps the series)")


# ── Settings ──────────────────────────────────────────────────────────────────
def _flag(v):
    return "on" if v else "off"


async def cmd_settings(link):
    print("=== SETTINGS ===")
    b = await link.request(FEAT_BASIC, label="request BASIC 0x13")
    if b is not None and len(b) >= 12:
        print(f"  BASIC 0x13: {xd(b)}")
        print(f"    button tones {_flag(b[1] & 0x02)}, auto light {_flag(not (b[1] & 0x04))}, "
              f"light {'3 s' if b[2] else '1.5 s'}, air-pressure kcal {_flag(b[8] & 0x04)}, "
              f"compass auto-correction {_flag(b[8] & 0x08)}, display bit0={b[1] & 0x01}")
    s = await link.request(FEAT_FEAT_2F, label="request SENSOR_CFG 0x2f")
    if s is not None and len(s) >= 3:
        print(f"  SENSOR 0x2f: {xd(s)}")
        print(f"    altitude interval {'2 min (12 h)' if s[1] & 0x04 else '5 s (1 h)'}, "
              f"display bit3={1 if s[1] & 0x08 else 0}, byte2={s[2]:#04x}")
    n = await link.request(FEAT_BLE_SETTINGS, label="request BLE_SETTINGS 0x11")
    if n is not None and len(n) >= 15:
        print(f"  BLE 0x11: {xd(n)}")
        print(f"    auto time sync {_flag(not (n[12] & 0x80))}, app connection timeout {n[14]} min")
    m = await link.request(FEAT_MODE_CUST, label="request MODE_CUST 0x38")
    if m is not None and len(m) >= 17:
        modes = [MODE_NAMES.get(x, str(x)) for x in m[1:9] if x != 0xff]
        hidden = [MODE_NAMES[i] for i in range(1, 9) if i not in m[1:9]]
        screens = [SCREEN_NAMES.get(x, str(x)) for x in m[9:17] if x != 0xff]
        print(f"  MODES 0x38: {xd(m)}")
        print(f"    mode carousel: {modes}" + (f"  (hidden: {hidden})" if hidden else ""))
        print(f"    display screens (cycle order): {screens}")


def _setbit(pkt, idx, mask, on):
    pkt[idx] = (pkt[idx] | mask) if on else (pkt[idx] & ~mask & 0xff)
    return pkt


async def cmd_set(link, key, value):
    """Read-modify-write of one documented settings bit."""
    onoff = value.lower() in ('on', '1', 'true', 'yes')
    if key == 'tones':
        feat, edit = FEAT_BASIC, lambda p: _setbit(p, 1, 0x02, onoff)
    elif key == 'autolight':
        feat, edit = FEAT_BASIC, lambda p: _setbit(p, 1, 0x04, not onoff)   # bit set = disabled
    elif key == 'lightdur':
        feat, edit = FEAT_BASIC, lambda p: (p.__setitem__(2, 0x01 if value in ('3', '3s') else 0x00) or p)
    elif key == 'airkcal':
        feat, edit = FEAT_BASIC, lambda p: _setbit(p, 8, 0x04, onoff)
    elif key == 'compass':
        feat, edit = FEAT_BASIC, lambda p: _setbit(p, 8, 0x08, onoff)
    elif key == 'altint':
        feat, edit = FEAT_FEAT_2F, lambda p: _setbit(p, 1, 0x04, value in ('2min', '2m', '2'))
    elif key == 'autosync':
        feat, edit = FEAT_BLE_SETTINGS, lambda p: _setbit(p, 12, 0x80, not onoff)  # bit set = disabled
    elif key == 'timeout':
        if value not in ('3', '5', '10'):
            print("  timeout must be 3, 5 or 10 (minutes)"); return
        feat, edit = FEAT_BLE_SETTINGS, lambda p: (p.__setitem__(14, int(value)) or p)
    else:
        print("  keys: tones autolight lightdur airkcal compass altint autosync timeout"); return
    out = await link.request_echo(feat, label=f"read 0x{feat:02x} for set {key}", edit=edit)
    if out is not None:
        print(f"  Written: {xd(out)}")


async def cmd_modecfg(link, which, item, onoff):
    """Show/hide a mode (list [1:9]) or a display screen (list [9:17]) in 0x38.

    The app semantics: hiding removes the id and shifts the rest left with ff
    padding; showing appends the id at the first ff slot. Hiding a mode also
    disables its functions on the watch (e.g. alarms)."""
    names = MODE_NAMES if which == 'mode' else SCREEN_NAMES
    try:
        idx = int(item)
    except ValueError:
        idx = next((i for i, n in names.items() if n.lower().startswith(item.lower())), None)
    if idx not in names:
        print(f"  unknown {which} {item!r}; ids: " +
              ", ".join(f"{i}={n}" for i, n in names.items())); return
    want_on = onoff == 'on'
    lo, hi = (1, 9) if which == 'mode' else (9, 17)

    def edit(p):
        cur = [x for x in p[lo:hi] if x != 0xff]
        if want_on and idx not in cur:
            cur.append(idx)
        elif not want_on and idx in cur:
            cur.remove(idx)
        p[lo:hi] = bytes(cur) + b'\xff' * (hi - lo - len(cur))
        return p
    out = await link.request_echo(FEAT_MODE_CUST, label=f"read 0x38 for {which} {idx}", edit=edit)
    if out is not None:
        print(f"  Written: {xd(out)}")
        if which == 'mode' and not want_on:
            print("  note: the watch disables the hidden mode's functions (e.g. alarms)")


# ── Alarms / countdown timer ──────────────────────────────────────────────────
async def cmd_alarms(link):
    print("=== ALARMS ===")
    a1 = await link.request(FEAT_ALARM1, label="request ALARM1 0x15")
    if a1 is not None and len(a1) >= 5:
        print(f"  1: {a1[3]:02d}:{a1[4]:02d} {_flag(a1[1] & 0x40)}")
    a = await link.request(FEAT_ALARMS, label="request ALARMS 0x16")
    if a is not None and len(a) >= 17:
        for i in range(4):
            g = a[1 + 4 * i:5 + 4 * i]
            print(f"  {i + 2}: {g[2]:02d}:{g[3]:02d} {_flag(g[0] & 0x40)}")


async def cmd_alarm(link, n, hhmm, onoff):
    h, m = (int(x) for x in hhmm.split(':'))
    en = 0x40 if onoff == 'on' else 0x00
    if n == 1:
        await link.w_all(bytes([FEAT_ALARM1, en, 0x40, h, m]), "write ALARM1")
        return
    pkt = await link.request(FEAT_ALARMS, label="request ALARMS 0x16")
    if pkt is None or len(pkt) < 17:
        print("  TIMEOUT: 0x16"); return
    b = bytearray(pkt[:17])
    for i in range(4):                    # the app writes 0x40 at byte 1 of every group
        b[2 + 4 * i] = 0x40
    off = 1 + 4 * (n - 2)
    b[off], b[off + 2], b[off + 3] = en, h, m
    await link.w_all(bytes(b), "write ALARMS 2-5")


async def cmd_timer(link):
    pkt = await link.request(FEAT_CDT, label="request CDT 0x18")
    if pkt is not None and len(pkt) >= 4:
        print(f"  Countdown timer: {pkt[1]}:{pkt[2]:02d}:{pkt[3]:02d}")


async def cmd_settimer(link, hms):
    h, m, s = (int(x) for x in hms.split(':'))
    await link.w_all(bytes([FEAT_CDT, h, m, s]) + bytes(11), "write CDT")   # 15 bytes, as the app writes


# ── World time / DST ──────────────────────────────────────────────────────────
async def cmd_worldtime(link):
    print("=== WORLD TIME ===")
    d = await link.request(FEAT_DST_WATCH, label="request DST_WATCH 0x1d")
    s0 = await link.request(FEAT_DST_SETTING, label="request DST_SETTING slot 0")
    s1 = await link.request(FEAT_DST_SETTING, label="request DST_SETTING slot 1")
    c0 = await link.request(FEAT_WORLD_CITY, bytes([FEAT_WORLD_CITY, 0x00]), "request WORLD_CITY 0")
    c1 = await link.request(FEAT_WORLD_CITY, bytes([FEAT_WORLD_CITY, 0x01]), "request WORLD_CITY 1")
    if d is None or len(d) < 9:
        print("  TIMEOUT: 0x1d"); return
    for slot, name, dst, code, s in ((0, c0, d[3], d[5] | (d[6] << 8), s0),
                                     (1, c1, d[4], d[7] | (d[8] << 8), s1)):
        label = "home " if slot == 0 else "world"
        nm = city_name(name) if name else '?'
        extra = f", slot bytes {xd(s[3:])}" if s else ""
        print(f"  {label}: {nm} (code {code}), DST {DST_MODES.get(dst, dst)}{extra}")


async def cmd_dst(link, mode):
    """Change the home DST mode inside a 0x21 transaction, rewriting the city block as the app does."""
    code = {'off': 0x00, 'on': 0x01, 'auto': 0x03}.get(mode)
    if code is None:
        print("  dst off|on|auto"); return
    await link.w_all(bytes([FEAT_TRANSACT, 0x00, 0x03]), "begin transaction 03")

    def set_home_dst(p):
        p[3] = code
        return p
    ok = await link.city_block(gps_chunks(), edit_dst_watch=set_home_dst)
    await link.w_all(bytes([FEAT_TRANSACT, 0x01, 0x03]), "end transaction 03")
    print("  DST mode written." if ok else "  (city block incomplete)")


# ── Misc ──────────────────────────────────────────────────────────────────────
async def cmd_appinfo(link):
    pkt = await link.request(FEAT_APP_INFO, label="request APP_INFO")
    if pkt is None:
        print("  TIMEOUT: APP_INFO"); return
    same = bytes(pkt[1:]) == APP_INFO_SEEN
    print(f"  APP_INFO: {xd(pkt)}  ({'same token as the captures' if same else 'different token'})")


async def cmd_raw(link, raw):
    """Write raw bytes to DATA_REQUEST_SP and show whatever comes back for 3 s."""
    await link.enable_data_notify()
    await link.drain(link.h0011_q)
    await link.drain(link.h0014_q)
    await link.w11(raw, "raw DATA_REQ write")
    await asyncio.sleep(3.0)
    await link.disable_data_notify()


def cmd_locind(args):
    if not args:
        target = "none" if _locind["dist"] is None else f"{_locind['dist']} m @ {_locind['bearing']}°"
        print(f"  Location Indicator: session={'open' if _locind['session'] else 'closed'}, target={target}")
    elif args[0] == 'off':
        _locind["dist"] = _locind["bearing"] = None
        print("  Target cleared — polls get 'nothing' (35 02 01)")
    elif len(args) == 2:
        _locind["dist"], _locind["bearing"] = int(args[0]), int(args[1]) % 360
        print(f"  Target set: {_locind['dist']} m @ {_locind['bearing']}° — "
              "sent on every poll of an open indicator session (watch connects with reason 07)")
    else:
        print("  Usage: locind <metres> <degrees> | locind off | locind")


# ── REPL ──────────────────────────────────────────────────────────────────────
HELP = """
Commands:
  lifelog [noack]        Fetch LIFE LOG: today, hourly bins, day history (ACK consumes them)
  mission [noack]        Fetch the mission-log block: altitude series + 14 event records
  status                 Fetch the 0x05/1c status block
  newdata                Read NEW_DATA (0x37)
  settings               Read and decode 0x13 / 0x2f / 0x11 / 0x38
  set <key> <value>      tones|autolight|airkcal|compass|autosync on|off, lightdur 1.5|3,
                         altint 2min|5s, timeout 3|5|10
  mode <id> <on|off>     Show/hide a mode in the carousel (0x38 [1:9]); id 1-8 or name prefix
  screen <id> <on|off>   Show/hide a timekeeping display screen (0x38 [9:17]); id 1-8 or prefix
  alarms                 Read alarms 1-5
  alarm <n> <HH:MM> <on|off>
  timer / settimer h:m:s Countdown timer (0x18)
  worldtime              Read home/world city state (0x1d / 0x1e / 0x1f)
  dst <off|on|auto>      Home DST mode, inside a 0x21 transaction
  locind <m> <deg>       Distance/bearing fed to the watch's Location Indicator; locind off
  time                   Write the current time
  appinfo                Read APP_INFO (0x22)
  req <feat> [byte]      ALL_REQ read of any feature id (hex), e.g. req 38 / req 1f 01
  wfeat <hex ...>        Write raw bytes to ALL_FEAT
  raw <hex ...>          Write raw bytes to DATA_REQUEST_SP and print the replies
  help / quit
"""


async def interactive_loop(link):
    loop = asyncio.get_event_loop()
    print(HELP)
    print("Ready. Type a command:")
    while True:
        if link.disconnected.is_set():
            return "disconnected"
        try:
            line = await loop.run_in_executor(None, lambda: input("\n> "))
        except (EOFError, KeyboardInterrupt):
            print("\nInterrupted.")
            return "quit"
        if link.disconnected.is_set():
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
            elif cmd == 'lifelog':
                await cmd_lifelog(link, ack=(len(parts) < 2 or parts[1] != 'noack'))
            elif cmd == 'mission':
                await cmd_mission(link, ack=(len(parts) < 2 or parts[1] != 'noack'))
            elif cmd == 'status':
                await cmd_status(link)
            elif cmd == 'newdata':
                await cmd_newdata(link)
            elif cmd == 'settings':
                await cmd_settings(link)
            elif cmd == 'set':
                if len(parts) != 3:
                    print("  Usage: set <key> <value>")
                else:
                    await cmd_set(link, parts[1].lower(), parts[2])
            elif cmd in ('mode', 'screen'):
                if len(parts) != 3 or parts[2].lower() not in ('on', 'off'):
                    print(f"  Usage: {cmd} <id 1-8|name prefix> <on|off>")
                else:
                    await cmd_modecfg(link, cmd, parts[1], parts[2].lower())
            elif cmd == 'alarms':
                await cmd_alarms(link)
            elif cmd == 'alarm':
                if len(parts) != 4 or not 1 <= int(parts[1]) <= 5:
                    print("  Usage: alarm <1-5> <HH:MM> <on|off>")
                else:
                    await cmd_alarm(link, int(parts[1]), parts[2], parts[3].lower())
            elif cmd == 'timer':
                await cmd_timer(link)
            elif cmd == 'settimer':
                if len(parts) != 2:
                    print("  Usage: settimer h:m:s")
                else:
                    await cmd_settimer(link, parts[1])
            elif cmd == 'worldtime':
                await cmd_worldtime(link)
            elif cmd == 'dst':
                await cmd_dst(link, parts[1].lower() if len(parts) > 1 else '')
            elif cmd == 'locind':
                cmd_locind(parts[1:])
            elif cmd == 'time':
                await link.write_time()
            elif cmd == 'appinfo':
                await cmd_appinfo(link)
            elif cmd == 'req':
                if len(parts) < 2:
                    print("  Usage: req <feat hex> [slot hex]")
                else:
                    feat = int(parts[1], 16)
                    payload = bytes([feat] + [int(x, 16) for x in parts[2:]])
                    pkt = await link.request(feat, payload)
                    print(f"  reply: {xd(pkt) if pkt else 'none'}")
            elif cmd == 'wfeat':
                await link.w_all(bytes(int(x, 16) for x in parts[1:]), "raw ALL_FEAT write")
            elif cmd == 'raw':
                raw = bytes(int(x, 16) for x in parts[1:])
                if not raw:
                    print("  Usage: raw <hex bytes>  e.g. raw 00 19 00 00 00")
                else:
                    await cmd_raw(link, raw)
            else:
                print(f"  Unknown command: {cmd!r}  (type 'help')")
        except Exception as e:
            print(f"\n  !! Command '{cmd}' failed: {type(e).__name__}: {e}")
            if not link.client.is_connected or link.disconnected.is_set():
                return "disconnected"
    return "quit"


# ── Main ──────────────────────────────────────────────────────────────────────
RECONNECT_DELAY = 3


async def main(addr):
    global _link
    first = True
    while True:
        link = CasioLink(on_all_feat=ggb100_events)
        _link = link
        _locind["session"] = False
        print(f"{'Connecting' if first else 'Reconnecting'} to {addr} … (press CONNECT on the watch)")
        first = False
        try:
            async with BleakClient(addr, timeout=60,
                                   disconnected_callback=link.on_disconnect) as client:
                link.attach(client)
                print(f"Connected! MTU={client.mtu_size}")
                if not await init_handshake(link):
                    print(f"Init failed — retrying in {RECONNECT_DELAY}s")
                    await asyncio.sleep(RECONNECT_DELAY)
                    continue
                reason = await interactive_loop(link)
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


if __name__ == "__main__":
    if len(sys.argv) > 1:
        ADDR = sys.argv[1]
    else:
        raise Exception("Invalid argument")
    asyncio.run(main(ADDR))
