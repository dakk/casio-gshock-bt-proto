#!/usr/bin/env python3
"""
casio_ble — BLE plumbing shared by the Casio G-SHOCK watches that expose the
26eb… "Casio Watch Features" service (GBD-200 and GG-B100 so far).

Only what PROTOCOL.md (GBD-200) and PROTOCOL-GGB100.md (GG-B100) describe
identically lives here:

  * the four characteristics and how each one is written
  * the feature ids present on both watches, with the same read/echo semantics
  * the 0x22 / 0x10 / 0x23 connection prefix
  * the 0x1d / 0x1e / 0x24 / 0x1f / 0x2f "city block" read-and-echo round
  * the 0x09 CURRENT_TIME packet
  * the plain DATA_REQUEST_SP fetch: 00 <feat> … → length echo → CONVOY → 04 <feat> …
  * the 0xfffe / 0xfffffffe "no data" sentinels and the BCD helpers

Model-specific things (XOR encodings, the GBD-200 CONVOY handshake, payload
layouts, extra init steps, the GG-B100 reason-byte flows) stay in the probes:
probe_casio.py (GBD-200) and probe_casio_ggb100.py (GG-B100).

Typical use:

    link = CasioLink(on_all_feat=my_hook)                # create before connecting
    async with BleakClient(addr, disconnected_callback=link.on_disconnect) as client:
        link.attach(client)
        await link.start()                                # ALL_FEAT notifications on
        app_info, ble_feat = await link.init_prefix("CASIO GG-B100")
        await link.city_block((gps_chunk(0, lat, lon), …))
        await link.write_time()
        raw = await link.fetch(0x11)                      # plain DATA_REQUEST_SP fetch
"""
import asyncio
import datetime
import struct
import time

# ── Characteristics ───────────────────────────────────────────────────────────
UUID_ALL_FEAT = "26eb002d-b012-49a8-b1f8-394fb2032b0f"  # ALL_FEATURES (h000e): WRITE_REQ + notify
UUID_ALL_REQ  = "26eb002c-b012-49a8-b1f8-394fb2032b0f"  # READ_REQUEST_FOR_ALL_FEATURES (h000c): write w/o response
UUID_DATA_REQ = "26eb0023-b012-49a8-b1f8-394fb2032b0f"  # DATA_REQUEST_SP (h0011): WRITE_REQ + notify
UUID_CONVOY   = "26eb0024-b012-49a8-b1f8-394fb2032b0f"  # CONVOY (h0014): notify (the GBD-200 also writes it)

# ── Feature ids with identical semantics on both watches ──────────────────────
FEAT_CURRENT_TIME = 0x09   # phone → watch; the last step of every init
FEAT_BLE_FEATURES = 0x10   # read; the GG-B100 reports its connection reason in byte 8
FEAT_BLE_SETTINGS = 0x11   # read/echo (on DATA_REQUEST_SP the same id fetches steps / LIFE LOG)
FEAT_BASIC        = 0x13   # read/echo, settings bitfield
FEAT_DST_WATCH    = 0x1d   # read/echo
FEAT_DST_SETTING  = 0x1e   # read twice (slot 0, slot 1), then echo both
FEAT_WORLD_CITY   = 0x1f   # read 1f 00 / 1f 01, then echo both
FEAT_VERSION_INFO = 0x20   # read
FEAT_APP_INFO     = 0x22   # read; 10-byte token + capability byte, written only at pairing
FEAT_WATCH_NAME   = 0x23   # phone → watch identity confirm
FEAT_GPS          = 0x24   # phone → watch, two chunks (chunk 1 means different things per model)
FEAT_WATCH_COND   = 0x28   # read
FEAT_FEAT_2F      = 0x2f   # read/echo

NO_DATA16 = 0xfffe         # "no data" in LE16 fields
NO_DATA32 = 0xfffffffe     # "no data" in LE32 fields


# ── Small helpers ─────────────────────────────────────────────────────────────
def xd(b, n=None):
    """Hex dump, optionally truncated to n bytes."""
    b = bytes(b)
    s = ' '.join(f'{x:02x}' for x in (b[:n] if n else b))
    return s + ('…' if n and len(b) > n else '')


def to_bcd(v):
    return ((v // 10) << 4) | (v % 10)


def from_bcd(b):
    return ((b >> 4) & 0x0f) * 10 + (b & 0x0f)


def bcd_datetime(b):
    """Decode a BCD yy mm dd hh mm [ss] timestamp; '-' when it is all 0xff."""
    b = bytes(b)
    if all(x == 0xff for x in b):
        return '-'
    f = [from_bcd(x) for x in b]
    s = f"20{f[0]:02d}-{f[1]:02d}-{f[2]:02d} {f[3]:02d}:{f[4]:02d}"
    if len(f) > 5:
        s += f":{f[5]:02d}"
    return s


def casio_dow(dt):
    """Casio day-of-week: Sunday = 0 … Saturday = 6."""
    return (dt.weekday() + 1) % 7


def time_packet(now=None):
    """0x09 CURRENT_TIME: year LE16, month, day, hour, min, sec (binary, local
    time), dow, fractions256 = 0, reason 1 = sync."""
    now = now or datetime.datetime.now()
    return bytes([FEAT_CURRENT_TIME,
                  now.year & 0xff, (now.year >> 8) & 0xff,
                  now.month, now.day, now.hour, now.minute, now.second,
                  casio_dow(now), 0x00, 0x01])


def watch_name_packet(name, length=19):
    """0x23 WATCH_NAME: ASCII name zero-padded to 19 bytes ("CASIO GBD-200", "CASIO GG-B100")."""
    raw = name.encode('ascii')[:length]
    return bytes([FEAT_WATCH_NAME]) + raw + bytes(length - len(raw))


def gps_chunk(slot, lat, lon):
    """0x24 chunk: 24 <slot> 01 <lat float64 BE> <lon float64 BE> 04."""
    return bytes([FEAT_GPS, slot, 0x01]) + struct.pack('>d', lat) + struct.pack('>d', lon) + bytes([0x04])


def data_req(feat, params=b'\x00\x00\x00'):
    """Plain DATA_REQUEST_SP request: 00 <feat> <params> (params = 00 00 00 for a whole block)."""
    return bytes([0x00, feat]) + bytes(params)


def data_ack(feat, params=b'\x00\x00\x00'):
    """DATA_REQUEST_SP ACK: 04 <feat> <params>."""
    return bytes([0x04, feat]) + bytes(params)


def city_name(pkt):
    """Name from a 0x1f reply (1f <slot> <ASCII, zero padded>)."""
    return bytes(pkt[2:]).split(b'\x00')[0].decode('ascii', 'replace')


# ── Connection object ─────────────────────────────────────────────────────────
class CasioLink:
    """
    One BLE connection to a Casio watch: notification queues, the four
    writers, and the exchanges both watches share.

    on_all_feat(data)      optional hook called for every ALL_FEAT notification
                           before it is queued (model-specific events).
    convoy_decoder(data)   optional; while `convoy_collecting` is true every
                           CONVOY notification is passed through it and the
                           returned bytes (or nothing, for None) are appended
                           to `convoy_buf`.  The GBD-200 sport fetch uses it
                           for its XOR'd, typed packets.
    """

    def __init__(self, client=None, on_all_feat=None, convoy_decoder=None):
        self.client = client
        self.on_all_feat = on_all_feat
        self.convoy_decoder = convoy_decoder
        self.all_feat_q = asyncio.Queue()
        self.h0011_q = asyncio.Queue()
        self.h0014_q = asyncio.Queue()
        self.convoy_buf = bytearray()
        self.convoy_collecting = False
        self.disconnected = asyncio.Event()
        self._data_notify_on = False

    def attach(self, client):
        self.client = client

    def on_disconnect(self, _client=None):
        """Pass as BleakClient(disconnected_callback=…)."""
        print("\r  [!] Watch disconnected")
        self.disconnected.set()

    # ── notification callbacks ──
    def _cb_all_feat(self, _, data):
        data = bytes(data)
        print(f"\r  [allFeat←] feat=0x{data[0]:02x} {len(data)}B  {xd(data, 16)}")
        if self.on_all_feat is not None:
            try:
                self.on_all_feat(data)
            except Exception as e:  # a hook must never kill the notification path
                print(f"  (on_all_feat hook error: {type(e).__name__}: {e})")
        self.all_feat_q.put_nowait(data)

    def _cb_h0011(self, _, data):
        data = bytes(data)
        print(f"\r  [h0011←] {xd(data)}")
        self.h0011_q.put_nowait(data)

    def _cb_h0014(self, _, data):
        data = bytes(data)
        print(f"\r  [h0014←] {len(data)}B  {xd(data, 24)}")
        if self.convoy_collecting and self.convoy_decoder is not None:
            dec = self.convoy_decoder(data)
            if dec:
                self.convoy_buf.extend(dec)
        self.h0014_q.put_nowait(data)

    # ── subscriptions ──
    async def start(self):
        """Subscribe to ALL_FEAT and drop anything already queued."""
        await self.client.start_notify(UUID_ALL_FEAT, self._cb_all_feat)
        await asyncio.sleep(0.1)
        await self.drain(self.all_feat_q)

    async def enable_data_notify(self, settle=0.2):
        """Enable the DATA_REQUEST_SP and CONVOY CCCDs (no-op if already on)."""
        if self._data_notify_on:
            return
        await self.client.start_notify(UUID_DATA_REQ, self._cb_h0011)
        await self.client.start_notify(UUID_CONVOY, self._cb_h0014)
        self._data_notify_on = True
        await asyncio.sleep(settle)

    async def disable_data_notify(self, settle=0.1):
        """Disable them again (errors ignored: the watch may already be gone)."""
        if not self._data_notify_on:
            return
        try:
            await self.client.stop_notify(UUID_DATA_REQ)
            await self.client.stop_notify(UUID_CONVOY)
        except Exception:
            pass
        self._data_notify_on = False
        await asyncio.sleep(settle)

    # ── writers ──
    async def w_all(self, data, lbl=""):
        print(f"  [allFeat→] {xd(data)}  {lbl}")
        await self.client.write_gatt_char(UUID_ALL_FEAT, bytes(data), response=True)

    async def w_req(self, data, lbl=""):
        print(f"  [allReq→] {xd(data)}  {lbl}")
        await self.client.write_gatt_char(UUID_ALL_REQ, bytes(data), response=False)

    async def w11(self, data, lbl=""):
        print(f"  [h0011→] {xd(data)}  {lbl}")
        await self.client.write_gatt_char(UUID_DATA_REQ, bytes(data), response=True)

    async def w14(self, data, lbl=""):
        print(f"  [h0014→] {xd(data)}  {lbl}")
        await self.client.write_gatt_char(UUID_CONVOY, bytes(data), response=False)

    # ── queue helpers ──
    async def drain(self, q):
        while not q.empty():
            q.get_nowait()

    def take(self, q, pred):
        """Non-blocking: pop items until one matches pred; None if none does."""
        while not q.empty():
            pkt = q.get_nowait()
            if pred(pkt):
                return pkt
        return None

    async def wait_for(self, q, pred, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                pkt = await asyncio.wait_for(q.get(), timeout=deadline - time.time())
                if pred(pkt):
                    return pkt
            except asyncio.TimeoutError:
                break
        return None

    # ── shared exchanges ──
    async def request(self, feat, payload=None, label=None, timeout=5):
        """ALL_REQ read of one feature: write [feat] (or the given payload, e.g.
        1f 01 for a slot) and return the ALL_FEAT reply with that id, or None."""
        payload = bytes([feat]) if payload is None else bytes(payload)
        await self.drain(self.all_feat_q)
        await self.w_req(payload, label or f"request 0x{feat:02x}")
        return await self.wait_for(self.all_feat_q, lambda d: d[0] == feat, timeout=timeout)

    async def request_echo(self, feat, payload=None, label=None, timeout=5, edit=None):
        """Read a feature and write the same bytes back (the read-modify-write
        pattern both apps use).  `edit(pkt) -> pkt` can change it in between."""
        pkt = await self.request(feat, payload, label, timeout)
        if pkt is None:
            print(f"  TIMEOUT: 0x{feat:02x}")
            return None
        out = bytes(pkt) if edit is None else bytes(edit(bytearray(pkt)))
        await self.w_all(out, f"echo 0x{feat:02x}")
        return out

    async def write_time(self, now=None):
        now = now or datetime.datetime.now()
        print(f"  Sending time: {now.strftime('%Y-%m-%d %H:%M:%S')} dow={casio_dow(now)}")
        await self.w_all(time_packet(now), "write current time")

    async def init_prefix(self, watch_name, timeout=5):
        """The first three steps of every connection on both watches:
             ALL_REQ 22 → APP_INFO, ALL_REQ 10 → BLE_FEATURES, then the
             WATCH_NAME identity write.
           Returns (app_info, ble_feat) or None on timeout."""
        app_info = await self.request(FEAT_APP_INFO, label="request APP_INFO", timeout=timeout)
        if app_info is None:
            print("  TIMEOUT: APP_INFO")
            return None
        ble_feat = await self.request(FEAT_BLE_FEATURES, label="request BLE_FEAT", timeout=timeout)
        if ble_feat is None:
            print("  TIMEOUT: BLE_FEAT")
            return None
        await self.w_all(watch_name_packet(watch_name), "write WATCH_NAME (identity confirm)")
        return app_info, ble_feat

    async def city_block(self, gps_chunks=(), timeout=5, edit_dst_watch=None):
        """The world-time round both apps run on every full init (and, on the
        GG-B100, inside every 0x21 transaction):
             1d read + echo
             1e slot 0 read, 1e slot 1 read, echo slot 0, echo slot 1
             24 chunks written blind
             1f 00 read, 1f 01 read, echo both
             2f read + echo
           `edit_dst_watch(pkt)` lets a caller modify the 1d block before the
           echo (DST mode changes).  Returns True, or False on a timeout."""
        if await self.request_echo(FEAT_DST_WATCH, label="request DST_WATCH_STATE 0x1d",
                                   timeout=timeout, edit=edit_dst_watch) is None:
            return False
        dst0 = await self.request(FEAT_DST_SETTING, label="request DST_SETTING slot 0", timeout=timeout)
        if dst0 is None:
            print("  TIMEOUT: DST_SETTING slot 0"); return False
        dst1 = await self.request(FEAT_DST_SETTING, label="request DST_SETTING slot 1", timeout=timeout)
        if dst1 is None:
            print("  TIMEOUT: DST_SETTING slot 1"); return False
        await self.w_all(bytes(dst0), "echo DST_SETTING slot 0")
        await self.w_all(bytes(dst1), "echo DST_SETTING slot 1")
        for i, chunk in enumerate(gps_chunks):
            await self.w_all(chunk, f"write GPS chunk {i} (0x24)")
        city0 = await self.request(FEAT_WORLD_CITY, bytes([FEAT_WORLD_CITY, 0x00]),
                                   "request WORLD_CITY slot 0", timeout)
        if city0 is None:
            print("  TIMEOUT: WORLD_CITY slot 0"); return False
        city1 = await self.request(FEAT_WORLD_CITY, bytes([FEAT_WORLD_CITY, 0x01]),
                                   "request WORLD_CITY slot 1", timeout)
        if city1 is None:
            print("  TIMEOUT: WORLD_CITY slot 1"); return False
        await self.w_all(bytes(city0), "echo WORLD_CITY slot 0")
        await self.w_all(bytes(city1), "echo WORLD_CITY slot 1")
        if await self.request_echo(FEAT_FEAT_2F, label="request FEAT_2F 0x2f", timeout=timeout) is None:
            return False
        return True

    async def fetch(self, feat, params=b'\x00\x00\x00', toggle_cccd=False, ack=True,
                    timeout=10, quiet=1.0):
        """The plain DATA_REQUEST_SP fetch used for steps (GBD-200) and for the
        LIFE LOG, mission-log and status blocks (GG-B100):
             phone → h0011  00 <feat> <params>
             watch → h0011  00 <feat> <len_lo> <len_hi> …   (echo; some blocks skip it)
             watch → h0014  payload, one or more notifications
             phone → h0011  04 <feat> <params>              (ACK; the watch then treats
                                                             the data as consumed)
           Returns the raw concatenated CONVOY bytes — undecoded, the GBD-200
           XORs them — or None if nothing arrived.  With toggle_cccd the
           DATA_REQ/CONVOY CCCDs are switched on before and off after, as the
           GG-B100 app does around every fetch."""
        if toggle_cccd:
            await self.enable_data_notify()
        await self.drain(self.h0011_q)
        await self.drain(self.h0014_q)
        await self.w11(data_req(feat, params), f"fetch 0x{feat:02x}")
        first = await self.wait_for(self.h0014_q, lambda d: True, timeout)
        if first is None:
            print(f"  TIMEOUT: no CONVOY data for 0x{feat:02x}")
            if toggle_cccd:
                await self.disable_data_notify()
            return None
        buf = bytearray(first)
        length = None
        echo = self.take(self.h0011_q, lambda d: len(d) >= 4 and d[0] == 0x00 and d[1] == feat)
        if echo is not None:
            length = echo[2] | (echo[3] << 8)
            print(f"  Incoming: {length} bytes")
        while length is None or len(buf) < length:
            pkt = await self.wait_for(self.h0014_q, lambda d: True, quiet)
            if pkt is None:
                break
            buf.extend(pkt)
        if ack:
            await self.w11(data_ack(feat, params), f"ACK 0x{feat:02x}")
        if toggle_cccd:
            await self.disable_data_notify()
        return bytes(buf)
