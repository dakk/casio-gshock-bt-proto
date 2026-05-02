#!/usr/bin/env python3
"""Deep analysis of btsnoop_hci_3.log - fix assembly, decode both summaries"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

GT = {
    '0x46e3': {'label':'Activity1','start':'2026-04-29 16:55:14','dist_m':2050,'dur_s':1569,'avg_s':763,'max_s':678,'kcal':72,'cad':104},
    '0x46e4': {'label':'Activity2','start':'2026-04-29 17:22:05','dist_m':300,'dur_s':249,'avg_s':805,'max_s':705,'kcal':10,'cad':103},
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
        except Exception:
            pass
    return res

def xd(data):
    d = bytearray(data)
    for i in range(1, len(d)): d[i] ^= 0xFF
    return bytes(d)

def bcd(b): return ((b>>4)&0xf)*10+(b&0xf)

def hexdump(data, off=0):
    for i in range(0, len(data), 16):
        c = data[i:i+16]
        print(f"    [{i+off:4d}] {' '.join(f'{b:02x}' for b in c)}")

def search_all(payload, values, label):
    for name, target, tol in values:
        hits = []
        for i in range(len(payload)-1):
            v = payload[i]|(payload[i+1]<<8)
            if abs(v-target)<=tol: hits.append(f"LE16[{i+3}]={v}")
        for i in range(len(payload)-3):
            v = payload[i]|(payload[i+1]<<8)|(payload[i+2]<<16)|(payload[i+3]<<24)
            if 0 < v <= target+tol and abs(v-target)<=tol: hits.append(f"LE32[{i+3}]={v}")
        print(f"  {name}={target}: {', '.join(hits) if hits else 'NOT FOUND'}")

# Load frames
f11 = frames_by_handle('0x0011')
f14 = frames_by_handle('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

# ── Collect sessions: group by distinct offset ────────────────────────────────
# For each feature-0x1e request with a new offset, collect 0x05 frames until next feature request
print("=== Collecting all 0x1e summaries ===")
summaries = {}  # offset_hex -> payload bytes
cur_offset = None
cur_data = bytearray()
prev_n = 0

def flush():
    global cur_offset, cur_data
    if cur_offset and cur_data:
        k = f"0x{cur_offset:04x}"
        if k not in summaries:
            summaries[k] = bytes(cur_data)
            print(f"  Saved summary at {k}: {len(cur_data)} bytes")
    cur_offset = None
    cur_data = bytearray()

for n, h, d in all_f:
    if h == '11' and len(d) >= 5 and d[0] == 0x00:
        fid = d[1]
        if fid == 0x1e:
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

# ── Decode each summary ───────────────────────────────────────────────────────
def p(pl, di):
    pi = di-3
    return pl[pi]&0xff if 0<=pi<len(pl) else 0

def ts(pl, di):
    yl,yh,mo,da,hh,mm,ss = [bcd(p(pl,di+k)) for k in range(7)]
    return f"{yh*100+yl:04d}-{mo:02d}-{da:02d} {hh:02d}:{mm:02d}:{ss:02d}"

for k,payload in summaries.items():
    gt = GT.get(k,{})
    print(f"\n{'='*60}")
    print(f"SUMMARY {k}  {gt.get('label','')}  ({len(payload)} bytes)")
    print(f"  Start : {ts(payload,150)}  (expected {gt.get('start','')})")
    print(f"  End   : {ts(payload,157)}")
    apr = p(payload,131); aps = p(payload,132)
    print(f"  Avg pace data[131/132]: {apr}'{aps:02d}''/km = {apr*60+aps} s/km  (expected {gt.get('avg_s','')})")
    rec = p(payload,137)
    print(f"  Records data[137]: {rec}  → 2s/rec={rec*2}s  (expected {gt.get('dur_s','')})")
    print(f"  Calories data[181]: {p(payload,181)}  (expected {gt.get('kcal','')})")
    print(f"  Cadence data[185]: {p(payload,185)}  (expected {gt.get('cad','')})")

    # Check if it's BCD for avg pace
    bcd_apr = bcd(p(payload,131)); bcd_aps = bcd(p(payload,132))
    print(f"  Avg pace BCD: {bcd_apr}'{bcd_aps:02d}''/km = {bcd_apr*60+bcd_aps} s/km")

    # Duration: try LE16 at various spots
    print(f"\n  --- Duration search ({gt.get('dur_s',0)}s) ---")
    dur = gt.get('dur_s',0)
    for i in range(len(payload)-1):
        v = payload[i]|(payload[i+1]<<8)
        if abs(v-dur)<=3: print(f"    LE16 payload[{i}] (data[{i+3}]) = {v}")
    for i in range(len(payload)-1):
        v = payload[i]*2
        if abs(v-dur)<=3: print(f"    byte*2 payload[{i}] (data[{i+3}]) = {payload[i]}*2={v}")

    print(f"\n  --- Distance search ({gt.get('dist_m',0)}m = {gt.get('dist_m',0)*10}dm = {gt.get('dist_m',0)*100}cm) ---")
    dist = gt.get('dist_m',0)
    search_all(payload, [
        ('meters',dist,5),('dm',dist*10,20),('cm',dist*100,200),
    ], k)

    print(f"\n  --- Max pace search ({gt.get('max_s',0)} s/km) ---")
    mxp = gt.get('max_s',0)
    mxm, mxs = mxp//60, mxp%60
    search_all(payload,[('max_pace_s',mxp,5)],'')
    for i in range(len(payload)-1):
        if payload[i]==mxm and payload[i+1]==mxs:
            print(f"    min/sec pair at payload[{i}:{i+2}] (data[{i+3}:{i+5}])")

    print(f"\n  --- All non-zero/non-ff bytes ---")
    for i,b in enumerate(payload):
        if b not in (0,0xff):
            print(f"    payload[{i:3d}] data[{i+3:3d}] = 0x{b:02x} = {b}")

# ── Full session list ─────────────────────────────────────────────────────────
print("\n=== Full 0x1d session list payload ===")
collecting = False
sl_data = bytearray()
for n, h, d in all_f:
    if h == '11' and len(d)>=2 and d[0]==0x00 and d[1]==0x1d:
        collecting = True; sl_data = bytearray()
    elif h == '11' and len(d)>=2 and d[0]==0x00 and d[1]!=0x1d and collecting:
        break
    elif h == '14' and collecting and d[0]==0x05:
        dec=xd(d); sl_data.extend(dec[3:])

print(f"  {len(sl_data)} bytes")
hexdump(sl_data)

# look for 0x46e3 and 0x46e4 in session list
print("\n  Searching for 0x46e3 and 0x46e4 in session list payload:")
for i in range(len(sl_data)-1):
    v = sl_data[i]|(sl_data[i+1]<<8)
    if v in (0x46e3,0x46e4):
        print(f"    payload[{i}:{i+2}] = 0x{v:04x}")

# ── Track record format (0x1f) ────────────────────────────────────────────────
print("\n=== 0x1f track data (first activity) ===")
collecting=False; tr_data=bytearray(); tr_count=0
for n, h, d in all_f:
    if h=='11' and len(d)>=2 and d[0]==0x00 and d[1]==0x1f and tr_count==0:
        collecting=True; tr_data=bytearray()
    elif h=='11' and len(d)>=2 and d[0]==0x00 and d[1] not in (0x1f,) and collecting:
        if d[1]==0x20:
            tr_count+=1
        if tr_count==0: break
    elif h=='14' and collecting and d[0]==0x05:
        dec=xd(d); tr_data.extend(dec[3:])

# Find non-ff/non-00 region
nz_start=0
for i,b in enumerate(tr_data):
    if b not in (0,0xff): nz_start=i; break

print(f"  Total {len(tr_data)} bytes; non-trivial data starts at [{nz_start}]")
print(f"  Bytes [{nz_start}:{nz_start+80}]:")
hexdump(tr_data[nz_start:nz_start+128], off=nz_start)

# Try 7-byte record: look at repeating pattern
print("\n  Checking 7-byte record size (stride 7):")
base = nz_start+2  # skip header bytes
for i in range(0, min(14*7, len(tr_data)-base), 7):
    chunk = tr_data[base+i:base+i+7]
    print(f"    rec[{i//7:2d}] = {' '.join(f'{b:02x}' for b in chunk)}")
