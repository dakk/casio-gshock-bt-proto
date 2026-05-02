#!/usr/bin/env python3
"""Separate track blocks and analyze activity1 and activity2 records"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

# Activity1: 2050m, 1569s, max=11'18''=678s/km, avg=12'43'', 3 segs
# Activity2:  300m,  249s, max=11'45''=705s/km, avg=13'25'', 1 seg

def run(args):
    return subprocess.run(args,capture_output=True,text=True).stdout.strip()

def frames(h):
    out = run(['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields','-e','frame.number','-e','btatt.value'])
    res=[]
    for line in out.split('\n'):
        p=line.strip().split('\t')
        try: res.append((int(p[0]),bytes.fromhex(p[1].replace(':',''))))
        except: pass
    return res

def xd(d):
    b=bytearray(d)
    for i in range(1,len(b)): b[i]^=0xFF
    return bytes(b)

f11=frames('0x0011'); f14=frames('0x0014')
all_f=sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

# Collect each 0x1f request separately
blocks = []   # list of (offset, data)
cur_off=None; cur_data=bytearray()

for n,h,d in all_f:
    if h=='11' and len(d)>=5 and d[0]==0x00 and d[1]==0x1f:
        off = d[3]|(d[4]<<8)
        if off != cur_off:
            if cur_off is not None and cur_data:
                blocks.append((cur_off, bytes(cur_data)))
            cur_off=off; cur_data=bytearray()
    elif h=='11' and len(d)>=2 and d[0]==0x00 and d[1]==0x20 and cur_off is not None:
        if cur_data: blocks.append((cur_off, bytes(cur_data)))
        cur_off=None; cur_data=bytearray()
    elif h=='14' and cur_off is not None and d[0]==0x05:
        dec=xd(d); cur_data.extend(dec[3:])

if cur_off is not None and cur_data:
    blocks.append((cur_off, bytes(cur_data)))

print(f"Got {len(blocks)} 0x1f blocks:")
for off, data in blocks:
    print(f"  offset=0x{off:04x}  size={len(data)} bytes")
    print(f"  header: {' '.join(f'{b:02x}' for b in data[:15])}")

# Activity1 track is at 0x47a0, activity2 at 0x4be0 (per protocol flow)
# From activity1 summary: ptr_old_track = 0x47a0, from activity2 summary: ptr_old_track = 0x4bf0

def analyze_block(label, data, expected_max_pace_s, expected_segs):
    print(f"\n{'='*60}")
    print(f"TRACK BLOCK: {label}")
    print(f"  Size: {len(data)} bytes")
    print(f"  Header: {' '.join(f'{b:02x}' for b in data[:15])}")

    # Header layout (15 bytes based on byte[0]=0x0f=15):
    # [0]=hdr_size, [1-2]=LE16 something, [3-4]=something, [5-6]=LE16 next_block_addr?, [7-14]=padding/flags
    hdr_size = data[0] if data[0] > 0 else 15
    val12 = data[1]|(data[2]<<8)
    val34 = data[3]|(data[4]<<8)
    val56 = data[5]|(data[6]<<8)
    print(f"  hdr[0]={data[0]}  LE16[1:3]={val12}(0x{val12:04x})  LE16[3:5]={val34}  LE16[5:7]=0x{val56:04x}")

    HEADER = hdr_size
    payload = data[HEADER:]
    num_recs = len(payload) // 7
    print(f"  Records (7-byte stride): {num_recs}")

    type_counts = {}
    min_pace = (99,99)
    seg_records = []

    for i in range(num_recs):
        rec = payload[i*7:(i+1)*7]
        if len(rec)<7: break
        t = rec[0]
        type_counts[t] = type_counts.get(t,0)+1
        pm,ps = rec[2],rec[3]
        if t==0x13 and pm>0 and pm<99:
            if (pm,ps) < min_pace:
                min_pace=(pm,ps)
        if t not in (0x00, 0x13):
            seg_records.append((i,rec))

    print(f"  Record type counts: {dict(sorted(type_counts.items()))}")
    print(f"  Fastest 0x13 pace: {min_pace[0]}'{min_pace[1]:02d}''/km = {min_pace[0]*60+min_pace[1]} s/km  (expected max={expected_max_pace_s})")

    # For 0x00 records: show non-zero bytes 2 and 3
    print(f"\n  Sample 0x00 records (first 15 with non-zero bytes):")
    shown=0
    for i in range(num_recs):
        rec = payload[i*7:(i+1)*7]
        if rec[0]==0x00 and (rec[2]!=0 or rec[3]!=0 or rec[4]!=0):
            print(f"    rec[{i:4d}] el={rec[1]:3d} [{rec[2]:3d},{rec[3]:3d}] cad={rec[4]:3d}  raw={' '.join(f'{b:02x}' for b in rec)}")
            shown+=1
            if shown>=15: break

    # All 0x13 records
    print(f"\n  All 0x13 records:")
    for i in range(num_recs):
        rec = payload[i*7:(i+1)*7]
        if rec[0]==0x13:
            t,el,pm,ps,cad = rec[0],rec[1],rec[2],rec[3],rec[4]
            print(f"    rec[{i:4d}] elapsed={el:4d} pace={pm}'{ps:02d}''/km cad={cad}  raw={' '.join(f'{b:02x}' for b in rec)}")

    # Last 10 records
    print(f"\n  Last 10 records:")
    for i in range(max(0,num_recs-10), num_recs):
        rec = payload[i*7:(i+1)*7]
        if len(rec)<7: break
        t,el,pm,ps,cad = rec[0],rec[1],rec[2],rec[3],rec[4]
        print(f"    rec[{i:4d}] type=0x{t:02x} elapsed={el:4d} pace={pm}'{ps:02d}'' cad={cad}  raw={' '.join(f'{b:02x}' for b in rec)}")

# Analyze the two blocks
if len(blocks) >= 1:
    analyze_block("Activity1 (0x47a0) - 2050m, max=11'18'', 3 segs", blocks[0][1], 678, 3)
if len(blocks) >= 2:
    analyze_block("Activity1 continued (0x4be0)", blocks[1][1], 678, 3)
