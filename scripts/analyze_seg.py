#!/usr/bin/env python3
"""Analyze segment boundaries and activity2 track format"""
import subprocess, os

LOG = os.path.join(os.path.dirname(__file__), 'btsnoop_hci_3.log')

def run(args):
    return subprocess.run(args,capture_output=True,text=True).stdout.strip()

def frames(h):
    out=run(['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields','-e','frame.number','-e','btatt.value'])
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

blocks={}; cur_off=None; cur_data=bytearray()
for n,h,d in all_f:
    if h=='11' and len(d)>=5 and d[0]==0x00 and d[1]==0x1f:
        off=d[3]|(d[4]<<8)
        if off != cur_off:
            if cur_off is not None:
                blocks[cur_off]=bytes(cur_data)
            cur_off=off; cur_data=bytearray()
    elif h=='11' and len(d)>=2 and d[0]==0x00 and d[1]==0x20 and cur_off is not None:
        if cur_data: blocks[cur_off]=bytes(cur_data)
        cur_off=None; cur_data=bytearray(); break
    elif h=='14' and cur_off is not None and d[0]==0x05:
        dec=xd(d); cur_data.extend(dec[3:])
if cur_off and cur_data: blocks[cur_off]=bytes(cur_data)

for off, data in sorted(blocks.items()):
    print(f'Block 0x{off:04x}: {len(data)} bytes, header={" ".join(f"{b:02x}" for b in data[:15])}')

# Activity1 block (0x47a0)
b1=blocks.get(0x47a0,b''); HEADER=15; payload=b1[HEADER:]; N=len(payload)//7
print(f'\nBlock1 (activity1): {N} records')

def show_rec(i, rec, prefix=''):
    if len(rec)<7: return
    minute, el, pm, ps, cad = rec[0], rec[1], rec[2], rec[3], rec[4]
    t = minute*60+el
    pace = f"{pm}'{ps:02d}''/km" if pm>0 else '---'
    b56 = f'{rec[5]:02x}{rec[6]:02x}'
    print(f'  {prefix}rec[{i:4d}] t={t:5d}s  min={minute:3d} el={el:3d}  pace={pace:12s}  cad={cad:3d}  b56={b56}  raw={rec.hex()}')

# Show segment 1 boundary area (t≈818s = min13 sec38 = rec≈408)
print('\n=== Activity1: around t=818s (seg1->seg2 boundary) ===')
for i in range(400, 420):
    rec=payload[i*7:(i+1)*7]
    show_rec(i, rec)

# Show all records with non-zero bytes[5:6]
print('\n=== Activity1: all records with non-zero bytes[5:6] ===')
count=0
for i in range(N):
    rec=payload[i*7:(i+1)*7]
    if len(rec)>=7 and (rec[5]!=0 or rec[6]!=0):
        show_rec(i, rec, '!!')
        count+=1
print(f'  Total: {count} records with non-zero b56')

# Activity2 block (0x4bf0)
b3=blocks.get(0x4bf0,b'')
print(f'\nBlock3 (activity2): {len(b3)} bytes, header={" ".join(f"{b:02x}" for b in b3[:15])}')
p3=b3[15:]; n3=len(p3)//7
print(f'Activity2 records: {n3}')
print('=== Activity2: first 20 records ===')
for i in range(min(20, n3)):
    rec=p3[i*7:(i+1)*7]
    show_rec(i, rec)

print('\n=== Activity2: all non-0xff records ===')
seg_transitions=[]
prev_b0=None
for i in range(n3):
    rec=p3[i*7:(i+1)*7]
    if len(rec)<7: break
    if rec[0]==0xff: break
    show_rec(i, rec)
    if prev_b0 is not None and rec[0] != prev_b0:
        seg_transitions.append((i, prev_b0, rec[0]))
    prev_b0=rec[0]

print(f'\n=== Activity2: byte[0] transitions (segment indicators?) ===')
for idx, prev, cur in seg_transitions:
    print(f'  At rec[{idx}]: 0x{prev:02x} -> 0x{cur:02x}')

# Continuation block (0x4be0) - first 20 records with various header sizes
print('\n=== Block2 (continuation 0x4be0): trying various header sizes ===')
b2=blocks.get(0x4be0,b'')
for hdr in [0,3,5,15]:
    p2=b2[hdr:]; n2=len(p2)//7
    rec0=p2[:7] if len(p2)>=7 else b''
    print(f'  hdr={hdr}: first_rec={rec0.hex()}  t={rec0[0]*60+rec0[1] if len(rec0)>=2 else "?"}s')
    # Look for minute=19 records (t=1140s+) to confirm continuation
    for i in range(n2):
        rec=p2[i*7:(i+1)*7]
        if len(rec)>=7 and rec[0]==19 and rec[1] in range(0,60,2):
            show_rec(i, rec, f'  hdr={hdr} min19 ')
            break
