#!/usr/bin/env python3
"""Analyze 0x1f track data for activity1 (2050m, 3 segments, max=11'18''/km)"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

def frames_by_handle(h):
    out = subprocess.run(['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields','-e','frame.number','-e','btatt.value'],
                         capture_output=True,text=True).stdout.strip()
    res = []
    for line in out.split('\n'):
        p = line.strip().split('\t')
        try: res.append((int(p[0]), bytes.fromhex(p[1].replace(':',''))))
        except: pass
    return res

def xd(d):
    b = bytearray(d)
    for i in range(1,len(b)): b[i] ^= 0xFF
    return bytes(b)

f11 = frames_by_handle('0x0011')
f14 = frames_by_handle('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

# Collect only the FIRST 0x1f block (for activity1, offset 0x47a0)
# Stop at the first 0x20 request
track = bytearray()
collecting = False
for n,h,d in all_f:
    if h=='11' and len(d)>=2 and d[0]==0x00 and d[1]==0x1f and not collecting:
        print(f"[{n}] Start 0x1f at offset 0x{(d[3]|(d[4]<<8)):04x}")
        collecting = True
    elif h=='11' and len(d)>=2 and d[0]==0x00 and d[1] in (0x20,0x1d,0x1e,0x1c) and collecting:
        print(f"[{n}] Stop (next feature 0x{d[1]:02x}), collected {len(track)} bytes")
        break
    elif h=='14' and collecting and d[0]==0x05:
        dec = xd(d); track.extend(dec[3:])

print(f"Total track bytes: {len(track)}")

# The track has a 15-byte header then 7-byte records
HEADER = 15
print(f"\nHeader bytes [0:{HEADER}]:")
print("  " + ' '.join(f'{b:02x}' for b in track[:HEADER]))

# Find all distinct record type bytes (byte 0 of each 7-byte record)
records_start = HEADER
num_recs = (len(track) - records_start) // 7
print(f"\nRecords starting at offset {records_start}: {num_recs} records")

# Scan all records, look for non-0x13 type bytes (segment markers)
seg_markers = []
min_pace = (99, 99)
max_pace_found = None

print("\n--- Non-0x13 type records (potential segment boundaries) ---")
for i in range(num_recs):
    base = records_start + i*7
    rec = track[base:base+7]
    if len(rec) < 7: break
    rtype, elapsed, p_min, p_sec, cad = rec[0], rec[1], rec[2], rec[3], rec[4]
    if rtype != 0x13:
        print(f"  rec[{i:4d}] t=0x{rtype:02x} elapsed={elapsed} pace={p_min}'{p_sec:02d}'' cad={cad}  raw={' '.join(f'{b:02x}' for b in rec)}")
        seg_markers.append((i, rtype, elapsed, p_min, p_sec, cad))
    else:
        # Track fastest pace
        if p_min > 0 and (p_min, p_sec) < min_pace:
            min_pace = (p_min, p_sec)

print(f"\nFastest pace in 0x13 records: {min_pace[0]}'{min_pace[1]:02d}''/km = {min_pace[0]*60+min_pace[1]} s/km")
print(f"(Expected max pace: 11'18'' = 678 s/km)")
print(f"\nFound {len(seg_markers)} non-0x13 records")

# Show records around segment boundaries in detail
print("\n--- Records around segment markers ---")
for idx, (ri, rtype, elapsed, p_min, p_sec, cad) in enumerate(seg_markers):
    print(f"\nSegment boundary at rec[{ri}] (type=0x{rtype:02x}):")
    for j in range(max(0,ri-3), min(num_recs, ri+4)):
        base = records_start + j*7
        rec = track[base:base+7]
        if len(rec) < 7: break
        t,e,pm,ps,c = rec[0],rec[1],rec[2],rec[3],rec[4]
        marker = " <<<<" if j==ri else ""
        print(f"  rec[{j:4d}] type=0x{t:02x} elapsed={e:3d} pace={pm}'{ps:02d}'' cad={c}{marker}")

# Show first 30 and last 10 records
print("\n--- First 30 records ---")
for i in range(min(30, num_recs)):
    base = records_start + i*7
    rec = track[base:base+7]
    if len(rec) < 7: break
    t,e,pm,ps,c = rec[0],rec[1],rec[2],rec[3],rec[4]
    print(f"  rec[{i:3d}] type=0x{t:02x} elapsed={e:3d}(={e}s) pace={pm}'{ps:02d}'' cad={c}")

print("\n--- Last 10 records ---")
for i in range(max(0, num_recs-10), num_recs):
    base = records_start + i*7
    rec = track[base:base+7]
    if len(rec) < 7: break
    t,e,pm,ps,c = rec[0],rec[1],rec[2],rec[3],rec[4]
    print(f"  rec[{i:3d}] type=0x{t:02x} elapsed={e:3d} pace={pm}'{ps:02d}'' cad={c}")
