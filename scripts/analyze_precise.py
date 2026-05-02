#!/usr/bin/env python3
"""
Precise analysis focusing on the real record structure and segment markers.
Key findings from analyze_final2.py:
- Records 60-132 in block1 have non-zero b5/b6 and seem misaligned
- Block1 has 580 records but only first ~60 are clean
- Block2 first record is t=1162s (minute 19, sec 22 = 0x13,0x16)
- Activity2 starts at t=2s (minute 0, sec 2) -> MINUTE-RESET confirmed
- The 11'18'' max pace appears at t=1046-1204s in block2 records 520-...
  but wait, block2 records are 0..215, so 520+ are in block1
"""
import subprocess
from collections import Counter

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'
HEADER = 15
STRIDE = 7
BLOCK_SIZE = 4080

def frames(h):
    out = subprocess.run(['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields',
                          '-e','frame.number','-e','btatt.value'],
        capture_output=True, text=True).stdout.strip()
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

def fmt_pace(p):
    if p <= 0 or p > 3600: return "  --:--"
    m, s = divmod(p, 60)
    return f"{m:3d}'{s:02d}''"

f11 = frames('0x0011'); f14 = frames('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

sessions = {}
sess_off = None
sess_data = bytearray()
for n, h, d in all_f:
    if h == '11' and len(d) >= 5 and d[0] == 0x00 and d[1] == 0x1f:
        off = d[3] | (d[4] << 8)
        if off != sess_off:
            if sess_off is not None and sess_off not in sessions:
                sessions[sess_off] = bytes(sess_data[:BLOCK_SIZE])
            sess_off = off
            sess_data = bytearray()
    elif h == '14' and d[0] == 0x05 and sess_off is not None:
        dec = xd(d)
        sess_data.extend(dec[3:])
if sess_off is not None and sess_off not in sessions:
    sessions[sess_off] = bytes(sess_data[:BLOCK_SIZE])

def get_recs(off, exclude_ff=True):
    data = sessions[off][:BLOCK_SIZE]
    payload = data[HEADER:]
    recs = []
    for i in range(len(payload)//STRIDE):
        r = payload[i*STRIDE:(i+1)*STRIDE]
        if exclude_ff and all(b == 0xff for b in r):
            continue
        recs.append({
            'idx': i, 'src': f'0x{off:04x}', 'raw': r,
            'min': r[0], 'sec': r[1],
            'abs_t': r[0]*60+r[1],
            'pace_s': r[2]*60+r[3],
            'cadence': r[4],
            'b5': r[5], 'b6': r[6],
        })
    return recs

recs1 = get_recs(0x47a0)
recs2 = get_recs(0x4be0)
recs3 = get_recs(0x4bf0)

# How many valid (non-ff) records?
print(f"Block 0x47a0: {len(recs1)} non-0xff records")
print(f"Block 0x4be0: {len(recs2)} non-0xff records")
print(f"Block 0x4bf0: {len(recs3)} non-0xff records")

# In block1, which records have b5/b6 non-zero AND the time seems wrong?
# The NON-MARKER records: b5==0, b6==0 - those are "clean" data records
# Let's look at clean records only
clean1 = [r for r in recs1 if r['b5'] == 0 and r['b6'] == 0]
clean2 = [r for r in recs2 if r['b5'] == 0 and r['b6'] == 0]
clean3 = [r for r in recs3 if r['b5'] == 0 and r['b6'] == 0]

print(f"\nClean records (b5=b6=0):")
print(f"  Block1: {len(clean1)}, Block2: {len(clean2)}, Block3: {len(clean3)}")

# Activity1 clean records timeline
act1_clean = clean1 + clean2
print(f"\n=== Activity1: all clean records, pace distribution ===")
print(f"  Total: {len(act1_clean)}")
if act1_clean:
    print(f"  First rec: t={act1_clean[0]['abs_t']}s idx={act1_clean[0]['idx']} raw={' '.join(f'{b:02x}' for b in act1_clean[0]['raw'])}")
    print(f"  Last rec:  t={act1_clean[-1]['abs_t']}s idx={act1_clean[-1]['idx']} raw={' '.join(f'{b:02x}' for b in act1_clean[-1]['raw'])}")

# Timeline of clean records in act1
print(f"\n  All clean records with valid pace (600-900 s/km = 10'-15'/km):")
seg_recs = [(r['abs_t'], r['pace_s'], r['idx'], r['src'], r['raw'], r['cadence'])
            for r in act1_clean if 600 <= r['pace_s'] <= 900]
seg_recs.sort(key=lambda x: x[0])
print(f"  Count: {len(seg_recs)}")
print(f"  By 30s windows:")
if seg_recs:
    max_t = seg_recs[-1][0]
    for w in range(0, max_t+30, 30):
        inw = [(t,p,idx,src,raw,cad) for t,p,idx,src,raw,cad in seg_recs if w <= t < w+30]
        if inw:
            avg = sum(p for t,p,idx,src,raw,cad in inw)//len(inw)
            mn = min(p for t,p,idx,src,raw,cad in inw)
            print(f"    t=[{w:5d}-{w+30:5d}s] avg={fmt_pace(avg)} n={len(inw)}")

# Now look at block1: records 29-60 where things get weird
print(f"\n=== Block1 records 29-75 to understand the 'marker' records ===")
for r in recs1[29:75]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    marker = " <MARKER>" if r['b5'] != 0 or r['b6'] != 0 else ""
    print(f"  rec[{r['idx']:3d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']:3d} b5={r['b5']:02x} b6={r['b6']:02x} {raw_s}{marker}")

print(f"\n=== Block1 records 560-580 (near end of block1) ===")
for r in recs1[560:]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"  rec[{r['idx']:3d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']:3d} b5={r['b5']:02x} b6={r['b6']:02x} {raw_s}")

print(f"\n=== Block2 records 0-10 (beginning of block2) ===")
for r in recs2[:10]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"  rec[{r['idx']:3d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']:3d} b5={r['b5']:02x} b6={r['b6']:02x} {raw_s}")

# Now: activity2 hypothesis check
print(f"\n=== Activity2: byte[0] analysis ===")
print("  Expected 249s = 4m09s -> byte[0] should reach min 4")
print(f"  Act2 clean records: {len(clean3)}")
if clean3:
    print(f"  First: t={clean3[0]['abs_t']}s byte[0]={clean3[0]['min']} byte[1]={clean3[1]['sec'] if len(clean3)>1 else '?'}")
    print(f"  Last:  t={clean3[-1]['abs_t']}s byte[0]={clean3[-1]['min']}")
    b0_vals = sorted(set(r['min'] for r in clean3))
    print(f"  byte[0] unique values: {b0_vals}")
    last_t = clean3[-1]['abs_t']
    print(f"  Last abs_t: {last_t}s (expected ~249s)")
    # Check if minute wraps properly
    print(f"\n  All clean records:")
    for r in clean3:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"    rec[{r['idx']:3d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']:3d} {raw_s}")

# Activity2 b5/b6 records
print(f"\n=== Activity2: first 10 marker (b5/b6 non-zero) records ===")
markers2 = [r for r in recs3 if r['b5'] != 0 or r['b6'] != 0]
for r in markers2[:10]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"  rec[{r['idx']:3d}] t={r['abs_t']:5d}s b5={r['b5']:02x} b6={r['b6']:02x} {raw_s}")

# Segment marker hypothesis:
# Looking at block1 records 60-132: all have b5=02,03,04
# and b6 increments by 2: 04,06,08,0a,...
# This looks like b5 = segment ID, b6 = some counter/index
# They cluster around t=817s (= 13'37'' into activity = end of segment 1)
print(f"\n=== SEGMENT MARKER ANALYSIS ===")
print("b5=02 group (segment transition marker?):")
b5_02 = [r for r in recs1 if r['b5'] == 0x02]
print(f"  Count: {len(b5_02)}, time range: {min(r['abs_t'] for r in b5_02)}..{max(r['abs_t'] for r in b5_02)}s")
print(f"  b6 values: {sorted(set(r['b6'] for r in b5_02))}")
for r in b5_02[:5]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"    rec[{r['idx']:3d}] t={r['abs_t']:5d}s {raw_s}")

b5_03 = [r for r in recs1 if r['b5'] == 0x03]
print(f"\nb5=03 group:")
print(f"  Count: {len(b5_03)}, time range: {min(r['abs_t'] for r in b5_03)}..{max(r['abs_t'] for r in b5_03)}s")

b5_04 = [r for r in recs1 if r['b5'] == 0x04]
print(f"\nb5=04 group:")
print(f"  Count: {len(b5_04)}, time range: {min(r['abs_t'] for r in b5_04)}..{max(r['abs_t'] for r in b5_04)}s")

# Now check: are b5=02,03,04 records overlapping the SEGMENT1 boundary at t=817s?
# Segment1 = 1km @ 13'38'' => ends at 818s
# The cluster of these records at t=817s could be a segment end marker!
print(f"\n=== SEGMENT BOUNDARY: First cluster at t~817s ===")
seg1_markers = [r for r in recs1 if 810 <= r['abs_t'] <= 820 and (r['b5'] != 0 or r['b6'] != 0)]
print(f"  Marker records at t=817-818s: {len(seg1_markers)}")
# What about t=705s and t=734s markers?
print(f"  Interpretation: b5=02 group spans t=165..817s")
print(f"  But all cluster near segment boundary t=817s")
print(f"  -> These are NOT segment markers per-record but rather some kind of")
print(f"     multi-data structure where the 7-byte stride is misinterpreted")

# Alternative: these 'marker' records are actually a different data structure
# interleaved with the 2-second records
# The b5 field incrementing (02->03->04) with b6 counting suggests
# these are chunk index fields: b5=chunk_major, b6=chunk_offset
# indicating this is part of a DIFFERENT data block fetched together with main records

# Let's count the REAL 2-second records in block1
real_recs = [r for r in recs1 if r['b5'] == 0 and r['b6'] == 0]
print(f"\n=== Block1 real 2-second records (b5=b6=0): {len(real_recs)} ===")
if real_recs:
    print(f"  Time range: {real_recs[0]['abs_t']}..{real_recs[-1]['abs_t']}s")
    print(f"  Last few:")
    for r in real_recs[-10:]:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"    rec[{r['idx']:3d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']:3d} {raw_s}")
