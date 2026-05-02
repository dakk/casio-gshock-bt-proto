#!/usr/bin/env python3
"""
CORRECTED final analysis of Casio GBD-200 BLE track data.
Key insight: each block request is duplicated (sent twice), yielding 8160 bytes,
but only the first 4080 bytes per unique offset are real data.
"""
import subprocess
from collections import Counter

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'
HEADER = 15
STRIDE = 7
BLOCK_SIZE = 4080  # real data per block

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

def fmt_pace(pace_s):
    if pace_s <= 0 or pace_s > 3600: return "--:--"
    m, s = divmod(pace_s, 60)
    return f"{m}'{s:02d}''"

f11 = frames('0x0011'); f14 = frames('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

# Collect sessions (first 4080 bytes per unique offset)
sessions = {}
sess_off = None
sess_data = bytearray()
seen_offs = set()

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

print(f"Blocks collected: {sorted(f'0x{k:04x}' for k in sessions)}")

def parse_block(off, label):
    data = sessions[off]
    hdr = data[:HEADER]
    payload = data[HEADER:]
    ff_trail = 0
    for b in reversed(payload):
        if b == 0xff: ff_trail += 1
        else: break
    useful = payload[:len(payload)-ff_trail]
    useful7 = useful[:len(useful)//7*7]
    n_recs = len(useful7) // 7
    recs = []
    for i in range(n_recs):
        r = useful7[i*7:(i+1)*7]
        recs.append({
            'idx': i, 'raw': r,
            'min': r[0], 'sec': r[1],
            'abs_t': r[0]*60+r[1],
            'pace_s': r[2]*60+r[3],
            'cadence': r[4],
            'b5': r[5], 'b6': r[6],
        })
    print(f"\n{'='*60}")
    print(f"Block 0x{off:04x} ({label}): {n_recs} records (payload={len(payload)}, ff_trail={ff_trail})")
    print(f"  Header: {' '.join(f'{b:02x}' for b in hdr)}")
    next_ptr = hdr[5]|(hdr[6]<<8)
    print(f"  next=0x{next_ptr:04x}")
    return recs

recs_47a0 = parse_block(0x47a0, "Act1 block1")
recs_4be0 = parse_block(0x4be0, "Act1 block2")
recs_4bf0 = parse_block(0x4bf0, "Act2")

act1 = recs_47a0 + recs_4be0
act2 = recs_4bf0

print(f"\nActivity1: {len(act1)} records total ({len(recs_47a0)} + {len(recs_4be0)})")
print(f"Activity2: {len(act2)} records")

# ── TASK 3: Activity2 byte[0] distribution ────────────────────────────────
print(f"\n{'='*60}")
print("TASK 3: Activity2 byte[0] distribution")
b0_cnt = Counter(r['min'] for r in act2)
print(f"  Unique byte[0] values: {sorted(b0_cnt.keys())}")
print(f"  Counts: {dict(sorted(b0_cnt.items()))}")
max_b0 = max(b0_cnt.keys())
min_b0 = min(b0_cnt.keys())
print(f"  Range: {min_b0}..{max_b0}")
if max_b0 <= 4 and min_b0 == 0:
    print("  -> MINUTE-RESET: activity-local time (0..4 min for 249s activity)")
elif max_b0 == 0x13:
    print("  -> ELAPSED/GLOBAL: same as act1 end (minute 19=0x13)")
else:
    print(f"  -> Mixed: max={max_b0} (0x{max_b0:02x})")

# ── Activity2 first 35 records (task 8) ───────────────────────────────────
print(f"\n{'='*60}")
print("TASK 8: Activity2 first 35 raw records")
print(f"  {'idx':>4} | {'raw':21} | b0 | b1 | abs_t | pace | cad | b5  b6")
for r in act2[:35]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    p_str = fmt_pace(r['pace_s']) if r['pace_s'] > 0 else "--:--"
    print(f"  {r['idx']:4d} | {raw_s} | {r['min']:2d} | {r['sec']:2d} | {r['abs_t']:5d}s | {p_str:8s} | {r['cadence']:3d} | {r['b5']:02x}  {r['b6']:02x}")

# Activity2 end
print(f"\n  Activity2 last 15 records (to see where activity ends):")
for r in act2[-15:]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    p_str = fmt_pace(r['pace_s']) if r['pace_s'] > 0 else "--:--"
    print(f"  {r['idx']:4d} | {raw_s} | {r['min']:2d} | {r['sec']:2d} | {r['abs_t']:5d}s | {p_str:8s} | {r['cadence']:3d}")

# ── TASK 4: Pace distribution act1 ───────────────────────────────────────
print(f"\n{'='*60}")
print("TASK 4: Activity1 pace distribution over time")
print("  Expected: Seg1 ends ~818s@13'38'', Seg2 ends ~1530s@11'52'', Seg3 39s@fast")
# Filter valid pace records (10-1500 s/km = 10s/km to 25 min/km)
valid = [(r['abs_t'], r['pace_s']) for r in act1 if 400 <= r['pace_s'] <= 1200]
valid.sort()
print(f"  Valid pace records (400-1200 s/km): {len(valid)}")
if valid:
    max_t = valid[-1][0]
    print(f"  Pace timeline (60s windows):")
    for w in range(0, max_t+60, 60):
        inw = [p for t,p in valid if w <= t < w+60]
        if inw:
            avg = sum(inw)//len(inw)
            mn = min(inw); mx = max(inw)
            print(f"    t=[{w:4d}-{w+60:4d}s] avg={fmt_pace(avg)} min={fmt_pace(mn)} max={fmt_pace(mx)} n={len(inw)}")

# ── TASK 5: Records with non-zero b5/b6 ──────────────────────────────────
print(f"\n{'='*60}")
print("TASK 5: Act1 records with non-zero byte[5] or byte[6]")
markers = [r for r in act1 if r['b5'] != 0 or r['b6'] != 0]
print(f"  Found {len(markers)} records with non-zero b5/b6")
if markers:
    print(f"  First 20:")
    for r in markers[:20]:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"    rec[{r['idx']:4d}] t={r['abs_t']:5d}s  {raw_s}  b5={r['b5']:02x} b6={r['b6']:02x}")
    print(f"  Last 5:")
    for r in markers[-5:]:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"    rec[{r['idx']:4d}] t={r['abs_t']:5d}s  {raw_s}  b5={r['b5']:02x} b6={r['b6']:02x}")
    # What b5 values appear?
    b5_cnt = Counter(r['b5'] for r in markers)
    print(f"  b5 value distribution: {dict(sorted(b5_cnt.items()))}")

# Act2 markers
markers2 = [r for r in act2 if r['b5'] != 0 or r['b6'] != 0]
print(f"\n  Act2: {len(markers2)} records with non-zero b5/b6")
for r in markers2[:10]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"    rec[{r['idx']:4d}] t={r['abs_t']:5d}s  {raw_s}")

# ── TASK 6: Segment boundaries ───────────────────────────────────────────
print(f"\n{'='*60}")
print("TASK 6: Segment boundary identification")
# Segment1: ~818s, Segment2: ~1530s
for target_t in [817, 818, 1530, 1569]:
    nearby = [r for r in act1 if abs(r['abs_t'] - target_t) <= 10]
    if nearby:
        print(f"\n  Records near t={target_t}s:")
        for r in nearby:
            raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
            print(f"    rec[{r['idx']:4d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} b5={r['b5']:02x} b6={r['b6']:02x}  {raw_s}")

# Look at block1 records 567-580 (boundary between block1 and block2)
print(f"\n  Block1 last 5 records and block2 first 5 records (continuity check):")
for r in recs_47a0[-5:]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"    blk1 rec[{r['idx']:4d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} {raw_s}")
for r in recs_4be0[:5]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"    blk2 rec[{r['idx']:4d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} {raw_s}")

# ── TASK 7: Fastest pace ─────────────────────────────────────────────────
print(f"\n{'='*60}")
print("TASK 7: Fastest pace records in act1 (looking for 11'18'' = 678 s/km)")
valid_p = [(r['abs_t'], r['pace_s'], r['idx'], r['raw']) for r in act1 if 400 <= r['pace_s'] <= 900]
valid_p.sort(key=lambda x: x[1])
print(f"  Top 15 fastest (400-900 s/km range):")
for t, p, idx, raw in valid_p[:15]:
    raw_s = ' '.join(f'{b:02x}' for b in raw)
    print(f"    rec[{idx:4d}] t={t:5d}s pace={fmt_pace(p)} ({p}s/km) {raw_s}")

# Records within 10s of 678 (11'18'')
close = [(t,p,idx,raw) for t,p,idx,raw in valid_p if abs(p-678) <= 10]
print(f"\n  Records within 10s/km of 678 (11'18''):")
for t,p,idx,raw in close[:20]:
    raw_s = ' '.join(f'{b:02x}' for b in raw)
    print(f"    rec[{idx:4d}] t={t:5d}s pace={fmt_pace(p)} ({p}s/km) {raw_s}")
print(f"  Total: {len(close)}")
if close:
    ts = [t for t,p,idx,raw in close]
    print(f"  Time range of max-pace records: {min(ts)}..{max(ts)}s")

# ── SUMMARY ───────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("SUMMARY")
print(f"  Block 0x47a0: {len(recs_47a0)} records, t={recs_47a0[0]['abs_t']}..{recs_47a0[-1]['abs_t']}s")
if recs_4be0:
    print(f"  Block 0x4be0: {len(recs_4be0)} records, t={recs_4be0[0]['abs_t']}..{recs_4be0[-1]['abs_t']}s")
print(f"  Activity1 combined: {len(act1)} records")
if act2:
    print(f"  Block 0x4bf0 (act2): {len(act2)} records, t={act2[0]['abs_t']}..{act2[-1]['abs_t']}s")
    print(f"  Act2 byte[0] range: {min(r['min'] for r in act2)}..{max(r['min'] for r in act2)}")
    max_b0 = max(r['min'] for r in act2)
    if max_b0 <= 4:
        print(f"  -> MINUTE-RESET hypothesis CONFIRMED (byte[0] 0..{max_b0})")
    elif max_b0 == 0x13:
        print(f"  -> ELAPSED hypothesis (byte[0]=0x13=19 throughout)")
    else:
        print(f"  -> max byte[0]={max_b0} (0x{max_b0:02x}) - verify")

# Check act1 max time
act1_valid_t = [r['abs_t'] for r in act1 if r['pace_s'] > 0 and r['pace_s'] < 2000]
if act1_valid_t:
    print(f"\n  Act1 valid-pace time range: {min(act1_valid_t)}..{max(act1_valid_t)}s (expected 1569s)")
    print(f"  -> Last valid pace time: {max(act1_valid_t)}s")
