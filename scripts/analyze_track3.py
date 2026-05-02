#!/usr/bin/env python3
"""Deep-dive into activity1 track block - find GPS records, segment markers, max pace"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

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

# Collect ONLY activity1 block (first 0x1f request at 0x47a0)
track1 = bytearray()
collecting = False
for n,h,d in all_f:
    if h=='11' and len(d)>=5 and d[0]==0x00 and d[1]==0x1f:
        off = d[3]|(d[4]<<8)
        if off == 0x47a0 and not collecting:
            print(f"[{n}] Start 0x1f at 0x{off:04x}")
            collecting = True
            track1 = bytearray()
    elif h=='11' and len(d)>=2 and d[0]==0x00 and d[1]==0x1f and collecting:
        off = d[3]|(d[4]<<8)
        if off != 0x47a0:
            print(f"[{n}] Next 0x1f at 0x{off:04x}, stopping activity1 collection ({len(track1)} bytes)")
            break
    elif h=='11' and len(d)>=2 and d[0]==0x00 and d[1] not in (0x1f,) and collecting:
        print(f"[{n}] Feature 0x{d[1]:02x}, stopping ({len(track1)} bytes)")
        break
    elif h=='14' and collecting and d[0]==0x05:
        dec=xd(d); track1.extend(dec[3:])

print(f"Activity1 block: {len(track1)} bytes")
HEADER=15
print(f"Header: {' '.join(f'{b:02x}' for b in track1[:HEADER])}")
print(f"  hdr[0]={track1[0]} (hdr_size)")
print(f"  LE16[1:3]=0x{track1[1]|(track1[2]<<8):04x} = {track1[1]|(track1[2]<<8)}")
print(f"  LE16[3:5]=0x{track1[3]|(track1[4]<<8):04x}")
print(f"  LE16[5:7]=0x{track1[5]|(track1[6]<<8):04x} (next_block_addr)")

payload = track1[HEADER:]
num_recs = len(payload)//7

print(f"\nTotal records (7-byte stride): {num_recs}")

# Show ALL records - look for patterns
print("\n--- All records (showing first 50 and non-trivial ones) ---")
for i in range(num_recs):
    rec = payload[i*7:(i+1)*7]
    if len(rec)<7: break
    t = rec[0]
    # Show if ANY byte is non-zero besides type
    if any(b!=0 for b in rec[1:]) or i < 50:
        tag=""
        if t==0x13: tag=" <<<< ACTIVITY2"
        elif t==0x00 and rec[4]>0: tag=f" cad={rec[4]}"
        elif t not in (0x00, 0xff): tag=" <SPECIAL>"
        print(f"  rec[{i:4d}] {' '.join(f'{b:02x}' for b in rec)}{tag}")
    if i > 580: break

# Focus on the special records around type transitions
print("\n--- Type pattern analysis (show type sequence) ---")
types=[payload[i*7] for i in range(min(num_recs,570))]
# Find runs of same type
prev=None; run_start=0; run_count=0
for i,t in enumerate(types):
    if t!=prev:
        if prev is not None and run_count>=3:
            print(f"  [{run_start:4d}-{i-1:4d}] type=0x{prev:02x}={prev:3d}, count={run_count}")
        prev=t; run_start=i; run_count=1
    else:
        run_count+=1
if run_count>=3:
    print(f"  [{run_start:4d}-{run_start+run_count-1:4d}] type=0x{prev:02x}={prev:3d}, count={run_count}")

# Look at the data around potential segment markers
# Segment1: 0-818s (1km @ 13'38'' avg = 818s)
# Segment2: 818-1530s (1km @ 11'52'' avg = 712s)
# Segment3: 1530-1569s (0.05km @ 39s)
print("\n--- Looking for segment boundaries ---")
print("  Segment1 ends around 818s, Segment2 ends around 1530s")
# In 0x00 records, elapsed is a single byte = 2*(record_index)?
# Or is elapsed cumulative?
# Check the elapsed field behavior:
elapsed_vals = []
for i in range(num_recs):
    rec = payload[i*7:(i+1)*7]
    if len(rec)<7: break
    if rec[0]==0x00:
        elapsed_vals.append((i, rec[1]))

print(f"\n  First 30 type-0x00 elapsed values:")
for i,(ri,el) in enumerate(elapsed_vals[:30]):
    print(f"    rec[{ri:4d}] elapsed=0x{el:02x}={el}")

print(f"\n  Last 30 type-0x00 elapsed values:")
for ri,el in elapsed_vals[-30:]:
    print(f"    rec[{ri:4d}] elapsed=0x{el:02x}={el}")

print(f"\n  Total type-0x00 records: {len(elapsed_vals)}")
if elapsed_vals:
    max_el = max(v for _,v in elapsed_vals)
    print(f"  Max elapsed value in 0x00 records: {max_el} (0x{max_el:02x})")

# Try 2-byte stride to see if GPS data uses different size
print("\n--- Trying 2-byte stride interpretation ---")
for i in range(0, min(100, len(payload)-1), 2):
    a,b = payload[i], payload[i+1]
    if a==0x00 and b>0:  # possibly start of a cadence record
        print(f"  2b[{i:4d}] 0x{a:02x} 0x{b:02x} = {a},{b}")

# Try 5-byte stride
print("\n--- Trying 5-byte stride (first 30 records) ---")
for i in range(30):
    rec = payload[i*5:(i+1)*5]
    if len(rec)<5: break
    print(f"  5b[{i:3d}] {' '.join(f'{b:02x}' for b in rec)}")

# Try 8-byte stride
print("\n--- Trying 8-byte stride (first 30 records) ---")
for i in range(30):
    rec = payload[i*8:(i+1)*8]
    if len(rec)<8: break
    print(f"  8b[{i:3d}] {' '.join(f'{b:02x}' for b in rec)}")

# Look at raw hex dump of first 200 bytes
print("\n--- Raw hex dump of payload[0:300] ---")
for i in range(0,300,16):
    c = payload[i:i+16]
    print(f"  [{i:4d}] {' '.join(f'{b:02x}' for b in c)}")
