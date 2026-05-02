#!/usr/bin/env python3
"""Find track address (0x47a0, 0x4bf0) and distance in 0x1e summary payloads"""
import subprocess, os

LOG = os.path.join(os.path.dirname(__file__), 'btsnoop_hci_3.log')

GT = {
    '0x46e3': {'label':'Activity1', 'track_addr':0x47a0, 'dist_m':2050},
    '0x46e4': {'label':'Activity2', 'track_addr':0x4bf0, 'dist_m':300},
}

def run(args):
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()

def frames_by_handle(h):
    out = run(['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields','-e','frame.number','-e','btatt.value'])
    res = []
    for line in out.split('\n'):
        parts = line.strip().split('\t')
        try:
            res.append((int(parts[0]), bytes.fromhex(parts[1].replace(':',''))))
        except:
            pass
    return res

def xd(data):
    d = bytearray(data)
    for i in range(1, len(d)): d[i] ^= 0xFF
    return bytes(d)

f11 = frames_by_handle('0x0011')
f14 = frames_by_handle('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

# Collect 0x1e summaries
summaries = {}
cur_offset = None
cur_data = bytearray()

def flush():
    global cur_offset, cur_data
    if cur_offset and cur_data:
        k = f"0x{cur_offset:04x}"
        if k not in summaries:
            summaries[k] = bytes(cur_data)
    cur_offset = None
    cur_data = bytearray()

for n, h, d in all_f:
    if h == '11' and len(d) >= 5 and d[0] == 0x00:
        if d[1] == 0x1e:
            off = d[3]|(d[4]<<8)
            if off != cur_offset:
                flush()
                cur_offset = off
                cur_data = bytearray()
        else:
            flush()
    elif h == '14' and cur_offset is not None and d[0] == 0x05:
        dec = xd(d)
        cur_data.extend(dec[3:])
flush()

print(f"Found {len(summaries)} summaries: {list(summaries.keys())}")

for k, payload in summaries.items():
    gt = GT.get(k, {})
    print(f"\n{'='*60}")
    print(f"SUMMARY {k} - {gt.get('label','?')}")
    print(f"  payload length: {len(payload)} bytes")

    # Search for track_addr as LE16 in payload (data[x:x+2] -> LE16)
    track_addr = gt.get('track_addr', 0)
    if track_addr:
        print(f"\n  Searching for track_addr 0x{track_addr:04x} = {track_addr}:")
        for i in range(len(payload)-1):
            v = payload[i]|(payload[i+1]<<8)
            if v == track_addr:
                print(f"    FOUND LE16 at payload[{i}] (data[{i+3}]): 0x{v:04x}")
            if abs(v - track_addr) <= 0x10:
                print(f"    NEAR  LE16 at payload[{i}] (data[{i+3}]): 0x{v:04x} (diff={v-track_addr:+d})")

    # Search for distance
    dist = gt.get('dist_m', 0)
    if dist:
        print(f"\n  Searching for distance {dist}m in various units:")
        for factor, unit_name in [(1,'m'), (10,'dm'), (100,'cm'), (5,'5m'), (2,'2m')]:
            target = dist // factor
            if dist % factor != 0:
                continue
            for i in range(len(payload)-1):
                v = payload[i]|(payload[i+1]<<8)
                if v == target:
                    print(f"    FOUND {unit_name}: LE16 at payload[{i}] (data[{i+3}]) = {v}")
            for i in range(len(payload)-3):
                v = payload[i]|(payload[i+1]<<8)|(payload[i+2]<<16)|(payload[i+3]<<24)
                if v == target and target < 0x10000:
                    print(f"    FOUND {unit_name}: LE32 at payload[{i}] (data[{i+3}]) = {v}")

    # Show ALL non-trivial bytes
    print(f"\n  All non-trivial bytes (not 0x00/0xff):")
    for i, b in enumerate(payload):
        if b not in (0x00, 0xff):
            print(f"    payload[{i:3d}] data[{i+3:3d}] = 0x{b:02x} = {b:3d}")
