#!/usr/bin/env python3
"""Final targeted analysis"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'
HEADER = 15
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
    for i in range(1, len(b)):
        b[i] ^= 0xFF
    return bytes(b)

def fmt_pace(p):
    if p <= 0 or p > 3600:
        return "--:--"
    m, s = divmod(p, 60)
    return f"{m}'{s:02d}''"

f11 = frames('0x0011')
f14 = frames('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11] + [(n,'14',d) for n,d in f14])

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

def get_useful_recs(off):
    data = sessions[off][:BLOCK_SIZE]
    payload = data[HEADER:]
    ff_trail = 0
    for b in reversed(payload):
        if b == 0xff:
            ff_trail += 1
        else:
            break
    useful = payload[:len(payload) - ff_trail]
    useful7 = useful[:len(useful) // 7 * 7]
    recs = []
    for i in range(len(useful7) // 7):
        r = useful7[i*7:(i+1)*7]
        recs.append({
            'idx': i, 'raw': r,
            'b0': r[0], 'b1': r[1],
            'abs_t': r[0]*60 + r[1],
            'pace_s': r[2]*60 + r[3],
            'cad': r[4],
            'b5': r[5], 'b6': r[6],
        })
    return recs

recs1 = get_useful_recs(0x47a0)
recs2 = get_useful_recs(0x4be0)
recs3 = get_useful_recs(0x4bf0)

print(f"Block1 useful: {len(recs1)} records")
print(f"Block2 useful: {len(recs2)} records")
print(f"Block3 useful: {len(recs3)} records")

# Block2 analysis
print(f"\n=== Block2 analysis ===")
b2_clean = [r for r in recs2 if r['b5'] == 0 and r['b6'] == 0]
b0_set = sorted(set(r['b0'] for r in b2_clean))
print(f"Block2 clean records: {len(b2_clean)}")
print(f"Block2 byte[0] values: {b0_set}")
if b2_clean:
    print(f"Block2 last clean: idx={b2_clean[-1]['idx']} t={b2_clean[-1]['abs_t']}s pace={fmt_pace(b2_clean[-1]['pace_s'])}")

# Block3 with byte[0] <= 13 (all meaningful records)
print(f"\n=== Block3: all records with byte[0] <= 13 ===")
for r in recs3:
    if r['b0'] <= 13:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        pace_str = fmt_pace(r['pace_s'])
        print(f"  rec[{r['idx']:3d}] t={r['abs_t']:4d}s b5={r['b5']:02x} b6={r['b6']:02x} pace={pace_str} cad={r['cad']:3d}  {raw_s}")

print(f"\n=== Block3 byte[0] distribution (all non-ff records) ===")
from collections import Counter
b0_cnt = Counter(r['b0'] for r in recs3)
print(f"  {dict(sorted(b0_cnt.items()))}")

# What does the 'marker' region look like? Are they re-packed data from elsewhere?
# In block1 at rec 60: `02 2d 6c 00 00 02 04`
# bytes[0:2] = 0x02, 0x2d = (2, 45) -> t = 2*60+45 = 165s
# bytes[2:4] = 0x6c, 0x00 = pace = 108*60+0 = 6480s/km -- INVALID
# bytes[5:6] = 0x02, 0x04 = b5, b6 which are incrementing
# BUT if we treat bytes[0:2] as something else:
# 0x02 = segment number? 0x2d = 45 = some index?
# The KEY insight: b6 is incrementing by 2 (like byte[1] in regular records)
# b5 is the "minute" equivalent -> 0x02, 0x03, 0x04
# So these ARE regular records but the data starts at b5 position!
# Let's check: are these records actually SHIFTED by 5 bytes?
print(f"\n=== Hypothesis: marker records are regular records shifted by 5 bytes ===")
print("rec[60] raw: 02 2d 6c 00 00 02 04")
print("  If we look at bytes [5:] + next record start:")
print("  b5=0x02, b6=0x04 -> 0x02*60+0x04 = 124s? No...")
print("  Or: the 7-byte record is actually stored differently in 'marker' region")

# Let's look at what the raw bytes form if we try different alignments
print(f"\n=== Block1 raw hex around the transition at record 59->60 ===")
data1 = sessions[0x47a0][:BLOCK_SIZE]
payload1 = data1[HEADER:]
start = 59 * 7  # record 59
print("Records 59-70 as continuous bytes:")
chunk = payload1[start:start + 12*7]
for i in range(0, len(chunk), 7):
    r = chunk[i:i+7]
    raw_s = ' '.join(f'{b:02x}' for b in r)
    idx = 59 + i//7
    b0 = r[0]; b1 = r[1]
    t = b0*60 + b1
    p = r[2]*60 + r[3]
    print(f"  rec[{idx}] {raw_s}  t={t}s pace={fmt_pace(p)} cad={r[4]} b5={r[5]:02x} b6={r[6]:02x}")

print(f"\n  Same region as 5-byte stride:")
for i in range(0, len(chunk)//5 * 5, 5):
    r = chunk[i:i+5]
    raw_s = ' '.join(f'{b:02x}' for b in r)
    print(f"  [+{i:3d}] {raw_s}")

# Final: where do the 11'18'' records actually sit in block1 clean records?
print(f"\n=== Block1 clean records near t=1000-1300s (act1 segment 2 fastest) ===")
b1_clean = [r for r in recs1 if r['b5'] == 0 and r['b6'] == 0]
for r in b1_clean:
    if 1000 <= r['abs_t'] <= 1300:
        raw_s = ' '.join(f'{b:02x}' for b in r['raw'])
        print(f"  rec[{r['idx']:3d}] t={r['abs_t']:5d}s pace={fmt_pace(r['pace_s'])} cad={r['cad']:3d}  {raw_s}")

# Combined act1 clean records
act1_clean = b1_clean + [r for r in recs2 if r['b5'] == 0 and r['b6'] == 0]
print(f"\n=== Activity1 ALL clean records pace summary ===")
print(f"Total clean records: {len(act1_clean)}")
if act1_clean:
    valid_p = [(r['abs_t'], r['pace_s']) for r in act1_clean if 600 <= r['pace_s'] <= 1400]
    valid_p.sort()
    print(f"Valid pace records (600-1400 s/km): {len(valid_p)}")
    print(f"Time range: {valid_p[0][0]}..{valid_p[-1][0]}s" if valid_p else "none")
    # Window analysis
    if valid_p:
        max_t = valid_p[-1][0]
        print(f"By 60s windows:")
        for w in range(0, max_t+60, 60):
            inw = [p for t,p in valid_p if w <= t < w+60]
            if inw:
                avg = sum(inw)//len(inw)
                mn = min(inw)
                mx = max(inw)
                print(f"  t=[{w:4d}-{w+60:4d}s] avg={fmt_pace(avg)} min={fmt_pace(mn)} max={fmt_pace(mx)} n={len(inw)}")

print(f"\n=== Max pace (11'18'' = 678 s/km) in clean records ===")
max_p_recs = [(r['abs_t'], r['pace_s'], r['idx'], r['raw']) for r in act1_clean if abs(r['pace_s'] - 678) <= 30]
max_p_recs.sort(key=lambda x: x[1])
print(f"Records within 30s/km of 678 (11'18''): {len(max_p_recs)}")
for t, p, idx, raw in max_p_recs[:10]:
    raw_s = ' '.join(f'{b:02x}' for b in raw)
    print(f"  rec[{idx:4d}] t={t:5d}s pace={fmt_pace(p)} ({p}s/km) {raw_s}")
if max_p_recs:
    ts = [t for t,p,idx,raw in max_p_recs]
    print(f"  Time range: {min(ts)}..{max(ts)}s")

# Activity2 clean summary
print(f"\n=== Activity2 clean records summary ===")
act2_clean = [r for r in recs3 if r['b5'] == 0 and r['b6'] == 0]
print(f"Total clean: {len(act2_clean)}")
if act2_clean:
    b0_set = sorted(set(r['b0'] for r in act2_clean))
    print(f"byte[0] values: {b0_set}")
    print(f"Time range: {act2_clean[0]['abs_t']}..{act2_clean[-1]['abs_t']}s")
    print(f"Expected: 0..249s (4m09s)")
    print(f"Hypothesis: MINUTE-RESET = {'YES' if max(b0_set) <= 4 else 'NO (max too large)'}")
