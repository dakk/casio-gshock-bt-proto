#!/usr/bin/env python3
"""
Final analysis of Casio GBD-200 BLE track data for btsnoop_hci_3.log
Tasks:
1. Parse all three blocks (each with 15-byte header)
2. Decode records: absolute_time_s = byte[0]*60 + byte[1]
3. Activity2 byte[0] value distribution
4. Pace distribution over time for activity1 (verify 3 segments)
5. All records with non-zero bytes[5:6] (segment markers?)
6. Segment boundary identification
7. Fastest pace records (looking for 11'18'' = 678s/km)
8. Block3 first 30 raw records
"""

import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

def frames(h):
    out = subprocess.run(
        ['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields',
         '-e','frame.number','-e','btatt.value'],
        capture_output=True, text=True).stdout.strip()
    res = []
    for line in out.split('\n'):
        p = line.strip().split('\t')
        try:
            res.append((int(p[0]), bytes.fromhex(p[1].replace(':',''))))
        except:
            pass
    return res

def xd(d):
    b = bytearray(d)
    for i in range(1, len(b)):
        b[i] ^= 0xFF
    return bytes(b)

# ── collect all frames sorted by frame number ──────────────────────────────
f11 = frames('0x0011')
f14 = frames('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11] + [(n,'14',d) for n,d in f14])

# ── collect blocks by offset ───────────────────────────────────────────────
blocks = {}
cur_off = None
cur_data = bytearray()

for n, h, d in all_f:
    if h == '11' and len(d) >= 5 and d[0] == 0x00 and d[1] == 0x1f:
        off = d[3] | (d[4] << 8)
        if off != cur_off:
            if cur_off is not None and cur_data:
                blocks[cur_off] = bytes(cur_data)
            cur_off = off
            cur_data = bytearray()
    elif h == '14' and cur_off is not None and d[0] == 0x05:
        dec = xd(d)
        cur_data.extend(dec[3:])

if cur_off is not None and cur_data:
    blocks[cur_off] = bytes(cur_data)

print(f"Collected {len(blocks)} blocks at offsets: {[f'0x{k:04x}' for k in sorted(blocks)]}")
for off in sorted(blocks):
    print(f"  Block 0x{off:04x}: {len(blocks[off])} bytes")

HEADER = 15
STRIDE = 7

def fmt_pace(pace_s_km):
    """Format pace in s/km -> mm'ss'' """
    if pace_s_km <= 0:
        return "  --:--"
    m = pace_s_km // 60
    s = pace_s_km % 60
    return f"{m:3d}'{s:02d}''"

def parse_block(data, label):
    """Parse one block: 15-byte header + 7-byte records."""
    hdr = data[:HEADER]
    print(f"\n{'='*60}")
    print(f"Block {label} (offset in context)")
    print(f"  Header ({HEADER}B): {' '.join(f'{b:02x}' for b in hdr)}")
    next_ptr = hdr[5] | (hdr[6] << 8)
    print(f"  next_block_ptr: 0x{next_ptr:04x}")
    payload = data[HEADER:]
    num_recs = len(payload) // STRIDE
    print(f"  Payload: {len(payload)} bytes => {num_recs} records @ 7-byte stride")
    return payload, num_recs

def decode_records(payload, num_recs, label):
    recs = []
    for i in range(num_recs):
        r = payload[i*STRIDE:(i+1)*STRIDE]
        if len(r) < STRIDE:
            break
        # hypothesis: absolute_time_s = byte[0]*60 + byte[1]
        # byte[0]=minute (0-indexed), byte[1]=second within minute (0,2,...,58)
        min_val  = r[0]
        sec_val  = r[1]
        abs_t    = min_val * 60 + sec_val
        # bytes[2:4] = pace (LE16? or two separate bytes?)
        # From known good: rec[33]=01 08 0d 25 66 00 00  => byte[2]=0x0d=13, byte[3]=0x25=37  => 13'37'' pace
        pace_min = r[2]
        pace_sec = r[3]
        pace_s   = pace_min * 60 + pace_sec  # s/km if non-zero
        cadence  = r[4]
        b5       = r[5]
        b6       = r[6]
        recs.append({
            'idx': i,
            'raw': r,
            'min': min_val,
            'sec': sec_val,
            'abs_t': abs_t,
            'pace_min': pace_min,
            'pace_sec': pace_sec,
            'pace_s': pace_s,
            'cadence': cadence,
            'b5': b5,
            'b6': b6,
        })
    return recs

# ─── Block analysis ────────────────────────────────────────────────────────
sorted_offs = sorted(blocks)

# Determine which blocks belong to which activity
# Activity1: starts at 0x47a0, chains to 0x4be0
# Activity2: starts at 0x4bf0

ACT1_OFFS = [0x47a0, 0x4be0]   # two chained blocks
ACT2_OFF  = 0x4bf0

for off in sorted_offs:
    data = blocks[off]
    hdr  = data[:HEADER]
    next_ptr = hdr[5] | (hdr[6] << 8)
    print(f"\nBlock 0x{off:04x}: header = {' '.join(f'{b:02x}' for b in hdr)}, next=0x{next_ptr:04x}, size={len(data)}")

# ─── Parse Block1 (activity1, part1) ──────────────────────────────────────
if 0x47a0 in blocks:
    payload1, n1 = parse_block(blocks[0x47a0], "0x47a0 (Act1 part1)")
    recs1 = decode_records(payload1, n1, "0x47a0")
else:
    print("Block 0x47a0 NOT FOUND")
    recs1 = []

# ─── Parse Block2 (activity1, part2) ──────────────────────────────────────
if 0x4be0 in blocks:
    payload2, n2 = parse_block(blocks[0x4be0], "0x4be0 (Act1 part2)")
    recs2 = decode_records(payload2, n2, "0x4be0")
else:
    print("Block 0x4be0 NOT FOUND")
    recs2 = []

# ─── Parse Block3 (activity2) ─────────────────────────────────────────────
if 0x4bf0 in blocks:
    payload3, n3 = parse_block(blocks[0x4bf0], "0x4bf0 (Act2)")
    recs3 = decode_records(payload3, n3, "0x4bf0")
else:
    print("Block 0x4bf0 NOT FOUND")
    recs3 = []

# ─── TASK 3: Activity2 byte[0] distribution ───────────────────────────────
print(f"\n{'='*60}")
print("TASK 3: Activity2 byte[0] value distribution")
if recs3:
    b0_vals = [r['min'] for r in recs3]
    from collections import Counter
    cnt = Counter(b0_vals)
    print(f"  Unique byte[0] values: {sorted(cnt.keys())}")
    print(f"  Counts: {dict(sorted(cnt.items()))}")
    print(f"  Min={min(b0_vals)}, Max={max(b0_vals)}")
    # For 249s activity: 0..3 min if minute-based (4'09'')
    # If elapsed-mode (byte[0]=total seconds//60?): 0..4
    # If all 0x13=19: continuation from act1
    print(f"\n  First 30 records of block3:")
    print(f"  {'idx':>4} | {'raw bytes':21} | byte[0] | byte[1] | abs_t_s | pace")
    for r in recs3[:30]:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        pace_str = fmt_pace(r['pace_s']) if r['pace_s'] > 0 else "  --:--"
        print(f"  {r['idx']:4d} | {raw_s} | {r['min']:7d} | {r['sec']:7d} | {r['abs_t']:7d} | {pace_str}")

# ─── TASK 4: Pace distribution for activity1 ──────────────────────────────
# Combine block1 + block2 for act1
act1_recs = recs1 + recs2

print(f"\n{'='*60}")
print(f"TASK 4: Activity1 pace distribution (total {len(act1_recs)} records)")
print(f"  Expected: Seg1=1km@13'38''/km (end ~818s), Seg2=1km@11'52''/km (end ~1530s), Seg3=0.05km@39s")
print(f"\n  Records with non-zero pace, grouped by 60s windows:")

# Build pace timeline
pace_records = [(r['abs_t'], r['pace_s']) for r in act1_recs if r['pace_s'] > 0]
pace_records.sort(key=lambda x: x[0])

if pace_records:
    max_t = max(t for t,p in pace_records)
    print(f"  Time range with pace: 0 .. {max_t}s")
    # Window averages
    WIN = 120  # 2-minute windows
    for w_start in range(0, max_t + WIN, WIN):
        w_end = w_start + WIN
        in_win = [p for t,p in pace_records if w_start <= t < w_end and p > 0]
        if in_win:
            avg_p = sum(in_win) // len(in_win)
            min_p = min(in_win)
            max_p = max(in_win)
            print(f"  t=[{w_start:4d}-{w_end:4d}s]  avg={fmt_pace(avg_p)}  min={fmt_pace(min_p)}  max={fmt_pace(max_p)}  n={len(in_win)}")

# ─── TASK 5: Non-zero bytes[5:6] (potential segment markers) ──────────────
print(f"\n{'='*60}")
print("TASK 5: All act1 records with non-zero byte[5] or byte[6]")
found_markers = False
for r in act1_recs:
    if r['b5'] != 0 or r['b6'] != 0:
        found_markers = True
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"  rec[{r['idx']:4d}] t={r['abs_t']:5d}s  {raw_s}  b5=0x{r['b5']:02x} b6=0x{r['b6']:02x}")
if not found_markers:
    print("  (none found)")

print("\nTask 5b: Activity2 records with non-zero byte[5] or byte[6]")
found_markers2 = False
for r in recs3:
    if r['b5'] != 0 or r['b6'] != 0:
        found_markers2 = True
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"  rec[{r['idx']:4d}] t={r['abs_t']:5d}s  {raw_s}  b5=0x{r['b5']:02x} b6=0x{r['b6']:02x}")
if not found_markers2:
    print("  (none found)")

# ─── TASK 6: Segment boundary identification ──────────────────────────────
print(f"\n{'='*60}")
print("TASK 6: Segment boundary identification in act1")
# Segment boundaries roughly at t=818s and t=1530s
for boundary_t in [800, 810, 818, 820, 830, 1520, 1530, 1540, 1550, 1560]:
    nearby = [(r['idx'], r['abs_t'], r['pace_s'], r['b5'], r['b6'], r['raw'])
              for r in act1_recs if abs(r['abs_t'] - boundary_t) <= 30]
    if nearby:
        print(f"\n  Around t={boundary_t}s:")
        for idx, t, p, b5, b6, raw in nearby:
            raw_s = ' '.join(f'{b:02x}' for b in raw)
            print(f"    rec[{idx:4d}] t={t:5d}s pace={fmt_pace(p)}  b5={b5:02x} b6={b6:02x}  raw={raw_s}")

# Look for pace transitions (large changes)
print(f"\n  Pace transition analysis (changes > 30s/km):")
prev_p = 0
for r in act1_recs:
    p = r['pace_s']
    if p > 0 and prev_p > 0:
        delta = abs(p - prev_p)
        if delta > 30:
            raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
            print(f"  rec[{r['idx']:4d}] t={r['abs_t']:5d}s pace={fmt_pace(p)}  prev={fmt_pace(prev_p)}  delta={delta}s  raw={raw_s}")
    if p > 0:
        prev_p = p

# ─── TASK 7: Fastest pace records ─────────────────────────────────────────
print(f"\n{'='*60}")
print("TASK 7: Fastest pace records (looking for 11'18'' = 678s/km)")
# Filter valid pace records (reasonable range 300-1200 s/km = 5..20 min/km)
valid_pace = [(r['abs_t'], r['pace_s'], r['idx'], r['raw'])
              for r in act1_recs if 300 <= r['pace_s'] <= 1200]
valid_pace.sort(key=lambda x: x[1])  # sort by pace ascending (fastest first)

print(f"  Top 20 fastest pace records in act1:")
for t, p, idx, raw in valid_pace[:20]:
    raw_s = ' '.join(f'{b:02x}' for b in raw)
    print(f"  rec[{idx:4d}] t={t:5d}s pace={fmt_pace(p)} ({p}s/km)  raw={raw_s}")

# Check if 678s/km (11'18'') appears
target = 678
close = [(t, p, idx, raw) for t, p, idx, raw in valid_pace if abs(p - target) <= 15]
print(f"\n  Records within 15s/km of 11'18'' (678s/km):")
for t, p, idx, raw in close:
    raw_s = ' '.join(f'{b:02x}' for b in raw)
    print(f"  rec[{idx:4d}] t={t:5d}s pace={fmt_pace(p)} ({p}s/km)  raw={raw_s}")

# ─── TASK 8: Block3 first 30 raw records ─────────────────────────────────
print(f"\n{'='*60}")
print("TASK 8: Block3 (activity2) first 30 raw records")
print(f"  Activity2 ground truth: 249s total, ~35 records at 2s each would be ~70 records")
print(f"  If minute-based: byte[0] should go 0..4")
print(f"  If all 0x13: same minute as act1 end (elapsed mode)")
if recs3:
    print(f"  Total records in block3: {len(recs3)}")
    print(f"\n  {'idx':>4} | {'raw (hex)':21} | b0 | b1 | abs_t | pace_s | cad | b5 | b6")
    for r in recs3[:30]:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"  {r['idx']:4d} | {raw_s} | {r['min']:2d} | {r['sec']:2d} | {r['abs_t']:5d} | {r['pace_s']:6d} | {r['cadence']:3d} | {r['b5']:02x} | {r['b6']:02x}")

# ─── Summary ───────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("SUMMARY")
if recs3:
    b0_set = sorted(set(r['min'] for r in recs3))
    last_act1_t = max(r['abs_t'] for r in act1_recs) if act1_recs else 0
    print(f"  Activity1: {len(act1_recs)} records, time range 0..{last_act1_t}s (expected ~1569s)")
    print(f"  Activity2: {len(recs3)} records, byte[0] values: {b0_set}")
    if b0_set == [0x13] or all(v == 0x13 for v in b0_set):
        print(f"  -> byte[0]=0x13=19 throughout act2: ELAPSED mode (not minute-reset)")
    elif 0 in b0_set and max(b0_set) <= 5:
        print(f"  -> byte[0] starts at 0, goes to {max(b0_set)}: MINUTE-RESET mode (activity-local)")
    else:
        print(f"  -> Mixed or unclear")

# Also show the actual act1 last few records to see where it ends
print(f"\n  Activity1 last 20 records:")
for r in act1_recs[-20:]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"  rec[{r['idx']:4d}] src={'blk2' if r['idx'] < n2 and len(recs1) > 0 and r in recs2 else 'blk1'} t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']} b5={r['b5']:02x} b6={r['b6']:02x}  raw={raw_s}")

print(f"\n  Activity2 last 10 records:")
for r in recs3[-10:]:
    raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
    print(f"  rec[{r['idx']:4d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cadence']} b5={r['b5']:02x} b6={r['b6']:02x}  raw={raw_s}")
