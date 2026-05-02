#!/usr/bin/env python3
"""Analyze btsnoop_hci_3.log - two activities on 29/04/2026"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

# Ground truth
GT = {
    1: {
        'start_utc': '2026-04-29 16:55:14',
        'dist_m': 2050,
        'duration_s': 1569,
        'avg_pace_s': 763,   # 12'43''
        'max_pace_s': 678,   # 11'18''
        'calories': 72,
        'cadence': 104,
        'segments': 3,
    },
    2: {
        'start_utc': '2026-04-29 17:22:05',
        'dist_m': 300,
        'duration_s': 249,
        'avg_pace_s': 805,   # 13'25''
        'max_pace_s': 705,   # 11'45''
        'calories': 10,
        'cadence': 103,
        'segments': 1,
    },
}

def run(args):
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()

def frames_by_handle(handle_hex):
    out = run(['tshark','-r',LOG,'-Y',f'btatt.handle == {handle_hex}',
               '-T','fields','-e','frame.number','-e','btatt.value'])
    frames = []
    for line in out.split('\n'):
        parts = line.strip().split('\t')
        try:
            fno = int(parts[0])
            data = bytes.fromhex(parts[1].replace(':',''))
            frames.append((fno, data))
        except Exception:
            pass
    return frames

def xor_dec(data):
    d = bytearray(data)
    for i in range(1, len(d)):
        d[i] ^= 0xFF
    return bytes(d)

def bcd(b):
    return ((b >> 4) & 0xf) * 10 + (b & 0xf)

def hexdump(data, label='', start=0):
    print(f"  {label}")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        print(f"    [{i+start:3d}] {h}")

def search(data, target, tol=20, label=''):
    hits = []
    for i in range(len(data)-1):
        v = data[i]|(data[i+1]<<8)
        if abs(v-target) <= tol:
            hits.append((i,'LE16',v))
    for i in range(len(data)-3):
        v = data[i]|(data[i+1]<<8)|(data[i+2]<<16)|(data[i+3]<<24)
        if abs(v-target) <= tol and v <= target+tol:
            hits.append((i,'LE32',v))
    if hits:
        print(f"  {label} ({target}): " + ', '.join(f"[{o}]{e}={v}" for o,e,v in hits))
    else:
        print(f"  {label} ({target}): NOT FOUND")
    return hits

# ── Load all frames ──────────────────────────────────────────────────────────
f0011 = frames_by_handle('0x0011')
f0014 = frames_by_handle('0x0014')
print(f"h0011 frames: {len(f0011)}  h0014 frames: {len(f0014)}")

all_frames = [(n,'0011',d) for n,d in f0011] + [(n,'0014',d) for n,d in f0014]
all_frames.sort()

# ── Protocol flow: find feature requests ─────────────────────────────────────
print("\n=== Feature requests on h0011 ===")
for n,h,d in all_frames:
    if h == '0011' and len(d) >= 2 and d[0] == 0x00:
        fid = d[1]
        off = (d[3]|(d[4]<<8)) if len(d) >= 5 else 0
        print(f"  [{n:5d}] feature=0x{fid:02x}  offset=0x{off:04x}")

# ── Collect 0x1e summary responses ──────────────────────────────────────────
print("\n=== Assembling 0x1e summaries ===")
summaries = []   # list of (request_frame, offset_requested, payload_bytes)
collecting = False
cur_offset = 0
cur_start = 0
cur_data = bytearray()

for n, h, d in all_frames:
    if h == '0011' and len(d) >= 5 and d[0] == 0x00 and d[1] == 0x1e:
        collecting = True
        cur_offset = d[3]|(d[4]<<8)
        cur_start = n
        cur_data = bytearray()
        continue
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] != 0x1e:
        if collecting and cur_data:
            summaries.append((cur_start, cur_offset, bytes(cur_data)))
        collecting = False
        cur_data = bytearray()
    if h == '0014' and collecting:
        if d[0] == 0x05:
            dec = xor_dec(d)
            cur_data.extend(dec[3:])
        elif d[0] == 0x06:
            pass  # control, ignore

# flush last
if collecting and cur_data:
    summaries.append((cur_start, cur_offset, bytes(cur_data)))

print(f"  Found {len(summaries)} 0x1e summary responses")
for i,(sf,so,sd) in enumerate(summaries):
    print(f"  Summary {i+1}: request_frame={sf}, offset=0x{so:04x}, payload={len(sd)} bytes")

# ── Decode each summary ───────────────────────────────────────────────────────
for idx, (sf, so, payload) in enumerate(summaries):
    # In Java terms: data[0]=type, data[1:3]=len, data[3:]=payload
    # So data[k] = payload[k-3]
    # Known offsets (data-relative, not payload-relative):
    gt = GT.get(idx+1, {})
    print(f"\n{'='*60}")
    print(f"SUMMARY {idx+1}  (frame {sf}, offset 0x{so:04x})")
    print(f"  Ground truth: {gt}")

    def p(name, di):
        """Get data[di] = payload[di-3]"""
        pi = di - 3
        if pi < 0 or pi >= len(payload):
            return 0
        return payload[pi] & 0xff

    def p16(name, di):
        return p(name,di) | (p(name,di+1)<<8)

    # Timestamps
    def ts(base_di):
        yl = bcd(p('',base_di))
        yh = bcd(p('',base_di+1))
        mo = bcd(p('',base_di+2))
        da = bcd(p('',base_di+3))
        hh = bcd(p('',base_di+4))
        mm = bcd(p('',base_di+5))
        ss = bcd(p('',base_di+6))
        return f"{yh*100+yl:04d}-{mo:02d}-{da:02d} {hh:02d}:{mm:02d}:{ss:02d} UTC"

    print(f"  Start : {ts(150)}  (expected {gt.get('start_utc','')})")
    print(f"  End   : {ts(157)}")
    print(f"  Avg pace: {p('',131)} min {p('',132)} sec = {p('',131)*60+p('',132)} s/km  (expected {gt.get('avg_pace_s','')})")
    print(f"  Records : {p('',137)}  → duration = {p('',137)*2}s  (expected {gt.get('duration_s','')})")
    print(f"  Calories: {p('',181)}  (expected {gt.get('calories','')})")
    print(f"  Cadence : {p('',185)}  (expected {gt.get('cadence','')})")
    print(f"  data[174]: {p('',174)} (0x{p('',174):02x})  [prev: step count]")
    print(f"  data[175]: {p('',175)} (0x{p('',175):02x})  [prev: distance ~m]")

    print(f"\n  --- Searching for distance {gt.get('dist_m',0)} m ---")
    pl = bytes(payload)
    search(pl, gt.get('dist_m',0), tol=5, label='dist_m LE')
    # in cm?
    search(pl, gt.get('dist_m',0)*100, tol=500, label='dist_cm LE')
    # in dm?
    search(pl, gt.get('dist_m',0)*10, tol=50, label='dist_dm LE')

    print(f"\n  --- Searching for max pace {gt.get('max_pace_s',0)} s/km ---")
    mxp = gt.get('max_pace_s',0)
    search(pl, mxp, tol=5, label='max_pace LE16')
    # as min/sec pair?
    mxp_min = mxp // 60
    mxp_sec = mxp % 60
    print(f"  max_pace as min={mxp_min} sec={mxp_sec}")
    for i in range(len(pl)-1):
        if pl[i] == mxp_min and pl[i+1] == mxp_sec:
            print(f"    FOUND at payload[{i}:{i+2}] (data[{i+3}:{i+5}])")

    print(f"\n  --- Searching for avg pace {gt.get('avg_pace_s',0)} s/km ---")
    avgp = gt.get('avg_pace_s',0)
    avgp_min = avgp // 60
    avgp_sec = avgp % 60
    print(f"  avg_pace as min={avgp_min} sec={avgp_sec} (currently reading data[131]/[132]={p('',131)}/{p('',132)})")

    print(f"\n  --- Searching for duration {gt.get('duration_s',0)} s ---")
    search(pl, gt.get('duration_s',0), tol=5, label='duration_s LE')

    print(f"\n  --- All non-trivial bytes (not 0x00/0xff) ---")
    for i,b in enumerate(pl):
        if b not in (0x00, 0xff):
            print(f"    payload[{i:3d}] (data[{i+3:3d}]) = 0x{b:02x} = {b}")

# ── Session list ─────────────────────────────────────────────────────────────
print("\n=== 0x1d session list responses ===")
collecting = False
cur_data = bytearray()
cur_start = 0

for n, h, d in all_frames:
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] == 0x1d:
        collecting = True
        cur_start = n
        cur_data = bytearray()
        continue
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] != 0x1d:
        if collecting and cur_data:
            dec = bytes(cur_data)
            print(f"  Session list (frame {cur_start}): {len(dec)} bytes")
            hexdump(dec[:32], 'first 32 bytes of session list data')
            raw9 = (~dec[9]) & 0xff if len(dec) > 9 else 0
            print(f"  raw[9]=0x{raw9:02x}  → formula offset=0x{0x46a0+0x40+((raw9+1)//2):04x}")
        collecting = False
        cur_data = bytearray()
    if h == '0014' and collecting and d[0] == 0x05:
        dec2 = xor_dec(d)
        cur_data.extend(dec2[3:])

if collecting and cur_data:
    dec = bytes(cur_data)
    print(f"  Session list (frame {cur_start}): {len(dec)} bytes")
    hexdump(dec[:64], 'first 64 bytes')
    raw9 = (~dec[9]) & 0xff if len(dec) > 9 else 0
    print(f"  raw[9]=0x{raw9:02x}  → formula offset=0x{0x46a0+0x40+((raw9+1)//2):04x}")

# ── 0x1c init response ───────────────────────────────────────────────────────
print("\n=== 0x1c init response (0x06 CONVOY after init request) ===")
init_done = False
for n, h, d in all_frames:
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] == 0x1c:
        print(f"  [{n}] Init request sent")
    if h == '0014' and not init_done and d[0] == 0x06:
        print(f"  [{n}] 0x06 response: {' '.join(f'{b:02x}' for b in d)}")
        init_done = True

# ── 0x1f/0x20 track data: first response only ────────────────────────────────
print("\n=== First 0x1f track response (old track) ===")
collecting = False
track_data = bytearray()
for n, h, d in all_frames:
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] == 0x1f:
        collecting = True
        track_data = bytearray()
        print(f"  [{n}] 0x1f request at offset 0x{(d[3]|(d[4]<<8)):04x}")
        continue
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] == 0x20:
        if collecting and track_data:
            print(f"  Assembled {len(track_data)} bytes of 0x1f track")
            hexdump(track_data[:80], 'first 80 bytes')
        collecting = False
        break
    if h == '0014' and collecting and d[0] == 0x05:
        dec2 = xor_dec(d)
        track_data.extend(dec2[3:])

print("\n=== First 0x20 track response (new track) ===")
collecting = False
track20 = bytearray()
for n, h, d in all_frames:
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and d[1] == 0x20:
        collecting = True
        track20 = bytearray()
        print(f"  [{n}] 0x20 request at offset 0x{(d[3]|(d[4]<<8)):04x}")
        continue
    if h == '0011' and len(d) >= 2 and d[0] == 0x00 and (d[1] == 0x1d or d[1] == 0x1c or d[1] == 0x1e):
        if collecting and track20:
            print(f"  Assembled {len(track20)} bytes of 0x20 track")
            hexdump(track20[:80], 'first 80 bytes')
        collecting = False
    if h == '0014' and collecting and d[0] == 0x05:
        dec2 = xor_dec(d)
        track20.extend(dec2[3:])

if collecting and track20:
    print(f"  Assembled {len(track20)} bytes of 0x20 track")
    hexdump(track20[:80], 'first 80 bytes')
